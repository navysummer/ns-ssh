//! Minimal PAM password authentication via runtime `dlopen` of the system
//! libpam. There is no compile-time link dependency (no `libpam-dev` header
//! needed), so the crate builds everywhere; `UsePAM yes` only takes effect
//! when a loadable libpam is present, and the password attempt fails (logged)
//! otherwise.
//!
//! ABI: `pam_start(service, user, conv, &mut pamh)`, `pam_authenticate`,
//! `pam_acct_mgmt`, `pam_end`, `pam_strerror` are identical on Linux and
//! macOS. The conversation callback is invoked by `pam_authenticate` to
//! obtain the password; we supply it from memory (no terminal prompt).

#[cfg(unix)]
mod imp {
    use std::ffi::{c_char, c_int, c_void, CString};

    type PamHandle = *mut c_void;

    type PamStart = unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const c_void, // pam_conv
        *mut PamHandle,
    ) -> c_int;
    type PamAuthenticate = unsafe extern "C" fn(PamHandle, c_int) -> c_int;
    type PamAcctMgmt = unsafe extern "C" fn(PamHandle, c_int) -> c_int;
    type PamEnd = unsafe extern "C" fn(PamHandle, c_int) -> c_int;

    const PAM_SUCCESS: c_int = 0;
    const PAM_CONV_ERR: c_int = 25;
    const PAM_SILENT: c_int = 0x8000;

    // pam_message { int msg_style; const char *msg; }: two machine words,
    // identical layout on Linux and macOS.
    #[repr(C)]
    struct PamMessage {
        msg_style: c_int,
        msg: *const c_char,
    }

    // pam_response { char *resp; int resp_retcode; }: `resp` is malloc'd and
    // later freed by PAM via free(3); `resp_retcode` is the app return code.
    #[repr(C)]
    struct PamResponse {
        resp: *mut c_char,
        resp_retcode: c_int,
    }

    // Message styles (pam_types.h); identical on Linux and macOS.
    const PAM_PROMPT_ECHO_OFF: c_int = 1;
    #[cfg(test)]
    const PAM_PROMPT_ECHO_ON: c_int = 2;
    #[cfg(test)]
    const PAM_ERROR_MSG: c_int = 3;
    #[cfg(test)]
    const PAM_TEXT_INFO: c_int = 4;

    // Pack the password for the callback: [len: usize][bytes]. usize keeps
    // the length exact for passwords beyond 255 bytes (a u8 would truncate).
    fn pack_password(password: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(std::mem::size_of::<usize>() + password.len());
        buf.extend_from_slice(&(password.len() as usize).to_ne_bytes());
        buf.extend_from_slice(password.as_bytes());
        buf
    }

    /// Conversation callback: PAM invokes it with the module's prompt messages
    /// and we respond with the caller-supplied password for echo-off prompts,
    /// and an empty string for echo-on/info/error messages (mirroring OpenSSH's
    /// `sshpam_conv`). Every response slot is allocated so a module issuing
    /// more than one message cannot cause an out-of-bounds read.
    ///
    /// Signature: `(num_msg, msg[], resp[], appdata) -> int`.
    unsafe extern "C" fn conv(
        num_msg: c_int,
        msg: *const c_void,
        resp: *mut *mut c_void,
        appdata: *mut c_void,
    ) -> c_int {
        if num_msg <= 0 || msg.is_null() || resp.is_null() || appdata.is_null() {
            return PAM_CONV_ERR;
        }
        let msg_arr = msg as *const PamMessage;
        let n = num_msg as usize;

        let responses = libc::calloc(n, std::mem::size_of::<PamResponse>());
        if responses.is_null() {
            *resp = std::ptr::null_mut();
            return PAM_CONV_ERR;
        }

        // appdata points to [len: usize][bytes].
        let pw = appdata as *const u8;
        let pass_len = *(pw as *const usize);
        let pass_bytes = std::slice::from_raw_parts(pw.add(std::mem::size_of::<usize>()), pass_len);
        let has_password = !pass_bytes.is_empty();

        for i in 0..n {
            let style = (*msg_arr.add(i)).msg_style;
            let slot = responses.cast::<PamResponse>().add(i);
            // resp_retcode is already 0 (calloc); only `resp` needs malloc'ing.
            let value: &[u8] = match style {
                PAM_PROMPT_ECHO_OFF if has_password => pass_bytes,
                _ => b"",
            };
            let copy = libc::malloc(value.len() + 1);
            if copy.is_null() {
                // Free the responses already produced, then bail.
                for j in 0..i {
                    let prev = responses.cast::<PamResponse>().add(j);
                    let p = (*prev).resp;
                    if !p.is_null() {
                        libc::free(p as *mut c_void);
                    }
                }
                libc::free(responses);
                *resp = std::ptr::null_mut();
                return PAM_CONV_ERR;
            }
            std::ptr::copy_nonoverlapping(value.as_ptr(), copy as *mut u8, value.len());
            *copy.cast::<u8>().add(value.len()) = 0;
            (*slot).resp = copy as *mut c_char;
        }

        *resp = responses;
        PAM_SUCCESS
    }

    struct PamLib {
        pam_start: PamStart,
        pam_authenticate: PamAuthenticate,
        pam_acct_mgmt: PamAcctMgmt,
        pam_end: PamEnd,
    }

    unsafe fn sym<T>(handle: *mut c_void, name: &[u8]) -> Option<T> {
        let p = libc::dlsym(handle, name.as_ptr() as *const c_char);
        if p.is_null() {
            None
        } else {
            Some(std::mem::transmute_copy::<*mut c_void, T>(&p))
        }
    }

    fn try_load() -> Option<PamLib> {
        for lib in [
            b"/usr/lib/libpam.dylib\0".as_slice(),
            b"libpam.dylib\0".as_slice(),
            b"libpam.so.0\0".as_slice(),
            b"libpam.so\0".as_slice(),
        ] {
            let handle = unsafe { libc::dlopen(lib.as_ptr() as *const c_char, libc::RTLD_NOW) };
            if handle.is_null() {
                continue;
            }
            if let (Some(start), Some(auth), Some(acct), Some(end)) = (
                unsafe { sym::<PamStart>(handle, b"pam_start\0") },
                unsafe { sym::<PamAuthenticate>(handle, b"pam_authenticate\0") },
                unsafe { sym::<PamAcctMgmt>(handle, b"pam_acct_mgmt\0") },
                unsafe { sym::<PamEnd>(handle, b"pam_end\0") },
            ) {
                return Some(PamLib {
                    pam_start: start,
                    pam_authenticate: auth,
                    pam_acct_mgmt: acct,
                    pam_end: end,
                });
            }
            unsafe { libc::dlclose(handle) };
        }
        None
    }

    // Loaded exactly once, thread-safely: `LazyLock` caches both the success
    // and the failure, removing the race where a second caller could otherwise
    // observe "attempt started but not finished" and wrongly fall back to
    // /etc/shadow.
    static PAM_LIB: std::sync::LazyLock<Option<PamLib>> = std::sync::LazyLock::new(try_load);

    fn load() -> Option<&'static PamLib> {
        PAM_LIB.as_ref()
    }

    /// True when a loadable libpam was found (and is therefore the PAM path,
    /// not the /etc/shadow fallback, that will serve a password attempt).
    pub fn pam_available() -> bool {
        load().is_some()
    }

    /// Verify `password` for `user` through the PAM stack for `service`.
    /// Returns `None` when libpam is unavailable (caller should fall back);
    /// otherwise `Some(ok)`.
    pub fn verify_pam_password(user: &str, password: &str, service: &str) -> Option<bool> {
        let lib = load()?;
        let user_c = CString::new(user).ok()?;
        let service_c = CString::new(service).ok()?;

        let pwbuf = pack_password(password);

        // pam_conv { int (*conv)(...); void *appdata; }: two machine words on
        // both Linux and macOS. Local stays valid for the whole pam_start..
        // pam_end window.
        let conv_fn = conv as *const c_void;
        let conv_struct: [usize; 2] = [conv_fn as usize, pwbuf.as_ptr() as usize];

        let mut pamh: PamHandle = std::ptr::null_mut();
        let rc = unsafe {
            (lib.pam_start)(
                service_c.as_ptr(),
                user_c.as_ptr(),
                conv_struct.as_ptr() as *const c_void,
                &mut pamh,
            )
        };
        if rc != PAM_SUCCESS || pamh.is_null() {
            return Some(false);
        }
        let auth_rc = unsafe { (lib.pam_authenticate)(pamh, PAM_SILENT) };
        let mut ok = auth_rc == PAM_SUCCESS;
        if ok {
            let acct_rc = unsafe { (lib.pam_acct_mgmt)(pamh, PAM_SILENT) };
            if acct_rc != PAM_SUCCESS {
                ok = false;
            }
        }
        let _ = unsafe { (lib.pam_end)(pamh, auth_rc) };
        Some(ok)
    }

    #[cfg(test)]
    mod conv_tests {
        use super::*;

        /// Drive `conv` directly with a set of message styles and a password,
        /// collecting the returned `pam_response` strings (and freeing them).
        fn run_conv(styles: &[c_int], password: &str) -> (c_int, Vec<String>) {
            let msgs: Vec<PamMessage> = styles
                .iter()
                .map(|&s| PamMessage {
                    msg_style: s,
                    msg: std::ptr::null(),
                })
                .collect();
            let pwbuf = pack_password(password);
            let mut resp: *mut c_void = std::ptr::null_mut();
            let rc = unsafe {
                conv(
                    msgs.len() as c_int,
                    msgs.as_ptr() as *const c_void,
                    &mut resp,
                    pwbuf.as_ptr() as *mut c_void,
                )
            };
            let mut out = Vec::new();
            if rc == PAM_SUCCESS && !resp.is_null() {
                let arr = resp as *const PamResponse;
                for i in 0..msgs.len() {
                    let r = unsafe { &*arr.add(i) };
                    let s = if r.resp.is_null() {
                        String::new()
                    } else {
                        unsafe { std::ffi::CStr::from_ptr(r.resp) }
                            .to_string_lossy()
                            .into_owned()
                    };
                    out.push(s);
                    if !r.resp.is_null() {
                        unsafe { libc::free(r.resp as *mut c_void) };
                    }
                }
                unsafe { libc::free(resp) };
            }
            (rc, out)
        }

        #[test]
        fn echo_off_prompt_returns_password() {
            let (rc, out) = run_conv(&[PAM_PROMPT_ECHO_OFF], "s3cret");
            assert_eq!(rc, PAM_SUCCESS);
            assert_eq!(out, vec!["s3cret".to_string()]);
        }

        #[test]
        fn multi_message_allocates_every_response_slot() {
            // A module issuing several messages (prompt + info + error) must
            // get one response slot per message — never an over-read.
            let (rc, out) = run_conv(&[PAM_PROMPT_ECHO_OFF, PAM_TEXT_INFO, PAM_ERROR_MSG], "pw");
            assert_eq!(rc, PAM_SUCCESS);
            assert_eq!(out, vec!["pw".to_string(), String::new(), String::new()]);
        }

        #[test]
        fn echo_on_and_unknown_styles_get_empty() {
            let (rc, out) = run_conv(&[PAM_PROMPT_ECHO_ON, 99], "pw");
            assert_eq!(rc, PAM_SUCCESS);
            assert_eq!(out, vec![String::new(), String::new()]);
        }

        #[test]
        fn password_longer_than_255_bytes_is_not_truncated() {
            let long = "a".repeat(300);
            let (rc, out) = run_conv(&[PAM_PROMPT_ECHO_OFF], &long);
            assert_eq!(rc, PAM_SUCCESS);
            assert_eq!(out, vec![long]);
        }

        #[test]
        fn empty_password_yields_empty_response() {
            let (rc, out) = run_conv(&[PAM_PROMPT_ECHO_OFF], "");
            assert_eq!(rc, PAM_SUCCESS);
            assert_eq!(out, vec![String::new()]);
        }

        #[test]
        fn invalid_args_return_conv_err() {
            let pwbuf = pack_password("x");
            let mut resp: *mut c_void = std::ptr::null_mut();
            let appdata = pwbuf.as_ptr() as *mut c_void;
            unsafe {
                assert_eq!(conv(0, std::ptr::null(), &mut resp, appdata), PAM_CONV_ERR);
                assert_eq!(conv(1, std::ptr::null(), &mut resp, appdata), PAM_CONV_ERR);
                assert_eq!(
                    conv(1, std::ptr::null(), std::ptr::null_mut(), appdata),
                    PAM_CONV_ERR
                );
                assert_eq!(
                    conv(1, std::ptr::null(), &mut resp, std::ptr::null_mut()),
                    PAM_CONV_ERR
                );
            }
        }
    }
}

#[cfg(not(unix))]
mod imp {
    pub fn verify_pam_password(_user: &str, _password: &str, _service: &str) -> Option<bool> {
        None
    }
    pub fn pam_available() -> bool {
        false
    }
}

pub fn verify_pam_password(user: &str, password: &str, service: &str) -> Option<bool> {
    imp::verify_pam_password(user, password, service)
}

/// True when a loadable libpam is present on this host (so `UsePAM yes`
/// actually routes password attempts through the PAM stack rather than the
/// /etc/shadow fallback).
pub fn pam_available() -> bool {
    imp::pam_available()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dlopen path must never panic, and when libpam is available the
    /// conversation wiring must tolerate an unknown user (returns Some(false)
    /// rather than crashing). This exercises `pam_start` + `pam_authenticate`
    /// end to end against the system PAM stack.
    #[test]
    fn pam_verifies_without_crashing() {
        let result = verify_pam_password("ns_ssh_no_such_user_xyz", "wrong-password", "sshd");
        // Either libpam is unavailable (None) or the unknown user is rejected
        // (Some(false)); a PAM stack must never authenticate an unknown user.
        assert!(result != Some(true), "PAM authenticated an unknown user");
    }

    /// Repeated calls (once the library is loaded) must stay consistent.
    #[test]
    fn pam_repeat_calls_are_stable() {
        let first = verify_pam_password("ns_ssh_no_such_user_xyz", "x", "sshd");
        let second = verify_pam_password("ns_ssh_no_such_user_xyz", "x", "sshd");
        assert_eq!(first, second);
    }
}
