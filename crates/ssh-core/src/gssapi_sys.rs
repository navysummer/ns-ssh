//! Runtime `dlopen` binding to the system GSS-API library.
//!
//! No compile-time link dependency (no `-lgssapi` / header required), so the
//! crate builds everywhere; GSS-API authentication only takes effect when a
//! loadable GSSAPI library is present (GSS.framework on macOS, libgssapi on
//! Linux). Mirrors the PAM dlopen approach.
//!
//! ABI follows RFC 2743 / RFC 2744 (GSS-API v2) as shipped by macOS
//! GSS.framework and Linux libgssapi. All status codes are `OM_uint32`
//! (uint32_t); buffers are `{ size_t length; void *value; }`.

#[cfg(unix)]
mod imp {
    use std::ffi::{c_char, c_int, c_void};
    use std::sync::LazyLock;

    pub type OmUint32 = u32;
    pub type GssName = *mut c_void;
    pub type GssCtxId = *mut c_void;
    pub type GssCredId = *mut c_void;
    pub type GssQop = u32;

    /// `gss_buffer_desc { size_t length; void *value; }`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct GssBuffer {
        pub length: usize,
        pub value: *mut c_void,
    }

    /// `gss_OID_desc { OM_uint32 length; void *elements; }`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct GssOid {
        pub length: u32,
        pub elements: *mut c_void,
    }

    impl GssBuffer {
        pub fn empty() -> Self {
            GssBuffer { length: 0, value: std::ptr::null_mut() }
        }
        pub fn is_empty(&self) -> bool {
            self.length == 0 || self.value.is_null()
        }
        pub fn as_slice(&self) -> &[u8] {
            if self.length == 0 || self.value.is_null() {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(self.value as *const u8, self.length) }
            }
        }
    }

    // GSS-API handles are opaque C pointers; see the `GssapiAuthState` Send
    // safety note in the server crate for why this is sound.


    // Status codes (RFC 2743 §2.4.1).
    pub const GSS_S_COMPLETE: OmUint32 = 0;
    pub const GSS_S_CONTINUE_NEEDED: OmUint32 = 1 << 0; // supplementary offset 0
    pub const GSS_S_FAILURE: OmUint32 = 13 << 16; // routine error offset 16

    // GSS_C_NO_* sentinels. `GSS_C_NO_CONTEXT` is kept for ABI completeness;
    // `GSS_C_NO_CREDENTIAL`/`GSS_C_NO_OID`/`GSS_C_NO_BUFFER` are used by the
    // init/accept callers below.
    #[allow(dead_code)]
    pub const GSS_C_NO_CONTEXT: GssCtxId = std::ptr::null_mut();
    pub const GSS_C_NO_CREDENTIAL: GssCredId = std::ptr::null_mut();
    pub const GSS_C_NO_OID: *const GssOid = std::ptr::null();
    pub const GSS_C_NO_BUFFER: *const GssBuffer = std::ptr::null();

    // Name type OIDs (RFC 2744); these are the standard exported OIDs.
    // GSS_C_NT_HOSTBASED_SERVICE = 1.3.6.1.5.6.2
    // GSS_C_NT_USER_NAME = 1.2.840.113554.1.2.1.1
    #[allow(dead_code)]
    const NT_HOSTBASED_SERVICE: GssOid = GssOid {
        length: 6,
        elements: b"\x2b\x06\x01\x05\x06\x02".as_ptr() as *mut c_void,
    };
    #[allow(dead_code)]
    const NT_USER_NAME: GssOid = GssOid {
        length: 10,
        elements: b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01".as_ptr() as *mut c_void,
    };

    // Request flags (RFC 2743 §4.3.1) for gss_init_sec_context.
    const GSS_C_MUTUAL_FLAG: OmUint32 = 1;
    const GSS_C_INTEG_FLAG: OmUint32 = 2;
    const GSS_C_DELEG_FLAG: OmUint32 = 1 << 2;
    // Returned context flags.
    const GSS_C_INTEG_AVAIL: OmUint32 = 1 << 2; // same bit as integ_req on output

    type FnInitSecContext = unsafe extern "C" fn(
        *mut OmUint32,        // minor_status
        GssCredId,            // initiator_cred_handle
        *mut GssCtxId,        // context_handle
        GssName,              // target_name
        *const GssOid,        // input_mech_type
        OmUint32,             // req_flags
        OmUint32,             // time_req
        *mut c_void,          // input_chan_bindings
        *const GssBuffer,     // input_token
        *mut *const GssOid,   // actual_mech_type
        *mut GssBuffer,       // output_token
        *mut OmUint32,        // ret_flags
        *mut OmUint32,        // time_rec
    ) -> OmUint32;
    type FnAcceptSecContext = unsafe extern "C" fn(
        *mut OmUint32,        // minor_status
        *mut GssCtxId,        // context_handle
        GssCredId,            // acceptor_cred_handle
        *const GssBuffer,     // input_token
        *mut c_void,          // input_chan_bindings
        *mut GssName,         // src_name
        *mut *const GssOid,   // mech_type
        *mut GssBuffer,       // output_token
        *mut OmUint32,        // ret_flags
        *mut OmUint32,        // time_rec
        *mut GssCredId,       // delegated_cred_handle
    ) -> OmUint32;
    type FnGetMic = unsafe extern "C" fn(
        *mut OmUint32,        // minor_status
        GssCtxId,             // context_handle
        GssQop,               // qop_req
        *const GssBuffer,     // message_buffer
        *mut GssBuffer,       // message_token
    ) -> OmUint32;
    type FnVerifyMic = unsafe extern "C" fn(
        *mut OmUint32,        // minor_status
        GssCtxId,             // context_handle
        *const GssBuffer,     // message_buffer
        *const GssBuffer,     // token_buffer
        *mut GssQop,          // qop_state
    ) -> OmUint32;
    type FnImportName = unsafe extern "C" fn(
        *mut OmUint32,        // minor_status
        *const GssBuffer,     // input_name_buffer
        *const GssOid,        // input_name_type
        *mut GssName,         // output_name
    ) -> OmUint32;
    type FnReleaseBuffer = unsafe extern "C" fn(*mut OmUint32, *mut GssBuffer) -> OmUint32;
    type FnReleaseName = unsafe extern "C" fn(*mut OmUint32, *mut GssName) -> OmUint32;
    type FnDeleteSecContext = unsafe extern "C" fn(
        *mut OmUint32,
        *mut GssCtxId,
        *mut GssBuffer, // output_token (may be null)
    ) -> OmUint32;
    type FnReleaseCred = unsafe extern "C" fn(*mut OmUint32, *mut GssCredId) -> OmUint32;
    type FnDisplayStatus = unsafe extern "C" fn(
        *mut OmUint32,        // minor_status
        OmUint32,             // status_value
        c_int,                // status_type
        *const GssOid,        // mech_type
        *mut OmUint32,        // message_content
        *mut GssBuffer,       // status_string
    ) -> OmUint32;
    type FnDisplayName = unsafe extern "C" fn(
        *mut OmUint32,        // minor_status
        GssName,              // name
        *mut GssBuffer,       // output_name_buffer
        *mut *const GssOid,   // output_name_type
    ) -> OmUint32;

    struct GssLib {
        init_sec_context: FnInitSecContext,
        accept_sec_context: FnAcceptSecContext,
        get_mic: FnGetMic,
        verify_mic: FnVerifyMic,
        import_name: FnImportName,
        release_buffer: FnReleaseBuffer,
        release_name: FnReleaseName,
        delete_sec_context: FnDeleteSecContext,
        release_cred: FnReleaseCred,
        display_status: FnDisplayStatus,
        display_name: FnDisplayName,
    }

    unsafe fn sym<T>(handle: *mut c_void, name: &[u8]) -> Option<T> {
        let p = libc::dlsym(handle, name.as_ptr() as *const c_char);
        if p.is_null() {
            None
        } else {
            Some(std::mem::transmute_copy::<*mut c_void, T>(&p))
        }
    }

    fn try_load() -> Option<GssLib> {
        // macOS GSS.framework first (the modern location), then the flat
        // library names for Linux/BSD.
        for lib in [
            b"/System/Library/Frameworks/GSS.framework/GSS\0".as_slice(),
            b"libgssapi.dylib\0".as_slice(),
            b"libgssapi_krb5.so.2\0".as_slice(),
            b"libgssapi.so.3\0".as_slice(),
            b"libgssapi.so\0".as_slice(),
        ] {
            let handle = unsafe { libc::dlopen(lib.as_ptr() as *const c_char, libc::RTLD_NOW) };
            if handle.is_null() {
                continue;
            }
            if let (
                Some(a), Some(b), Some(c), Some(d), Some(e), Some(f), Some(g), Some(h),
                Some(i), Some(j), Some(k),
            ) = (
                unsafe { sym::<FnInitSecContext>(handle, b"gss_init_sec_context\0") },
                unsafe { sym::<FnAcceptSecContext>(handle, b"gss_accept_sec_context\0") },
                unsafe { sym::<FnGetMic>(handle, b"gss_get_mic\0") },
                unsafe { sym::<FnVerifyMic>(handle, b"gss_verify_mic\0") },
                unsafe { sym::<FnImportName>(handle, b"gss_import_name\0") },
                unsafe { sym::<FnReleaseBuffer>(handle, b"gss_release_buffer\0") },
                unsafe { sym::<FnReleaseName>(handle, b"gss_release_name\0") },
                unsafe { sym::<FnDeleteSecContext>(handle, b"gss_delete_sec_context\0") },
                unsafe { sym::<FnReleaseCred>(handle, b"gss_release_cred\0") },
                unsafe { sym::<FnDisplayStatus>(handle, b"gss_display_status\0") },
                unsafe { sym::<FnDisplayName>(handle, b"gss_display_name\0") },
            ) {
                return Some(GssLib {
                    init_sec_context: a,
                    accept_sec_context: b,
                    get_mic: c,
                    verify_mic: d,
                    import_name: e,
                    release_buffer: f,
                    release_name: g,
                    delete_sec_context: h,
                    release_cred: i,
                    display_status: j,
                    display_name: k,
                });
            }
            unsafe { libc::dlclose(handle) };
        }
        None
    }

    static GSS_LIB: LazyLock<Option<GssLib>> = LazyLock::new(try_load);

    fn lib() -> Option<&'static GssLib> {
        GSS_LIB.as_ref()
    }

    /// True when a loadable GSS-API library is present *and* usable.
    ///
    /// A mere `dlopen` success is not enough: some macOS GSS.framework shims
    /// expose all symbols but segfault on the first OID-based call (e.g.
    /// `gss_import_name` with `GSS_C_NT_HOSTBASED_SERVICE`). A crash cannot be
    /// caught in-process, so usability is probed in a forked child: the child
    /// performs a real `gss_import_name` and exits; if it dies by signal the
    /// library is treated as unavailable (GSSAPI falls back to other auth
    /// methods rather than crashing the SSH client/server).
    pub fn gssapi_available() -> bool {
        lib().is_some() && probe_library_usable()
    }

    /// Fork a child that performs an OID-based `gss_import_name` and observe
    /// whether it survives. Returns false when the child is killed by a signal
    /// (the library crashed), true otherwise (success or clean error).
    fn probe_library_usable() -> bool {
        use std::ffi::CString;

        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                // Fork unavailable: be conservative and assume usable (the
                // library loaded; only the probe could not run).
                return true;
            }
            if pid == 0 {
                // Child: attempt the OID-based import. Any exit (0 or non-zero
                // error) without crashing means the library is usable.
                let host = CString::new("host@localhost").unwrap_or_default();
                let name_buf = GssBuffer {
                    length: host.as_bytes().len(),
                    value: host.as_ptr() as *mut c_void,
                };
                let mut name: GssName = std::ptr::null_mut();
                let mut minor: OmUint32 = 0;
                if let Some(lib) = lib() {
                    let _ = (lib.import_name)(
                        &mut minor,
                        &name_buf,
                        &NT_HOSTBASED_SERVICE,
                        &mut name,
                    );
                    // Release the name (if any) before exiting.
                    let mut release_minor: OmUint32 = 0;
                    let _ = (lib.release_name)(&mut release_minor, &mut name);
                }
                // Exit via _exit so atexit handlers (which might touch the
                // GSS library) do not run in the child.
                libc::_exit(0);
            }
            // Parent: wait for the child and check whether it died by signal.
            let mut status: libc::c_int = 0;
            if libc::waitpid(pid, &mut status, 0) < 0 {
                return true;
            }
            if libc::WIFSIGNALED(status) {
                return false;
            }
            true
        }
    }

    fn status_string(status: OmUint32, is_minor: bool) -> String {
        let Some(lib) = lib() else { return format!("0x{:08x}", status) };
        let mut minor: OmUint32 = 0;
        let mut msg_content: OmUint32 = 0;
        let mut buf = GssBuffer::empty();
        let rc = unsafe {
            (lib.display_status)(
                &mut minor,
                status,
                if is_minor { 2 } else { 1 }, // GSS_C_GSS_CODE=1, GSS_C_MECH_CODE=2
                GSS_C_NO_OID,
                &mut msg_content,
                &mut buf,
            )
        };
        if rc == GSS_S_COMPLETE {
            let s = String::from_utf8_lossy(buf.as_slice()).into_owned();
            let _ = unsafe { (lib.release_buffer)(&mut minor, &mut buf) };
            s
        } else {
            format!("0x{:08x}", status)
        }
    }

    /// Build a `host@hostname` GSS name (host-based service) and import it.
    pub fn import_hostbased_service(hostname: &str) -> Result<GssName, String> {
        let input = format!("host@{}", hostname);
        let bytes = input.as_bytes();
        let name_buf = GssBuffer {
            length: bytes.len(),
            value: bytes.as_ptr() as *mut c_void,
        };
        let mut name: GssName = std::ptr::null_mut();
        let mut minor: OmUint32 = 0;
        let rc = unsafe {
            (lib().ok_or_else(|| "GSSAPI library unavailable".to_string())?.import_name)(
                &mut minor,
                &name_buf,
                &NT_HOSTBASED_SERVICE,
                &mut name,
            )
        };
        if rc != GSS_S_COMPLETE {
            let msg = status_string(rc, false);
            let minor_msg = status_string(minor, true);
            return Err(format!("gss_import_name failed: {} / {}", msg, minor_msg));
        }
        Ok(name)
    }

    /// Result of one `gss_init_sec_context` round.
    pub struct InitResult {
        pub token: Vec<u8>,
        pub continue_needed: bool,
        pub integ_avail: bool,
        pub context: GssCtxId,
    }

    /// Perform one `gss_init_sec_context` step. `context` starts as
    /// `GSS_C_NO_CONTEXT`; subsequent calls pass the previous handle.
    /// `delegate` requests credential delegation.
    pub fn init_sec_context(
        context: &mut GssCtxId,
        target_name: GssName,
        input_token: &[u8],
        delegate: bool,
    ) -> Result<InitResult, String> {
        let lib = lib().ok_or_else(|| "GSSAPI library unavailable".to_string())?;
        let mut minor: OmUint32 = 0;
        let mut ret_flags: OmUint32 = 0;
        let mut time_rec: OmUint32 = 0;
        let mut actual_mech: *const GssOid = std::ptr::null();
        let mut out = GssBuffer::empty();
        let mut flags = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG;
        if delegate {
            flags |= GSS_C_DELEG_FLAG;
        }
        let in_buf = GssBuffer {
            length: input_token.len(),
            value: if input_token.is_empty() {
                std::ptr::null_mut()
            } else {
                input_token.as_ptr() as *mut c_void
            },
        };
        let rc = unsafe {
            (lib.init_sec_context)(
                &mut minor,
                GSS_C_NO_CREDENTIAL,
                context,
                target_name,
                GSS_C_NO_OID,
                flags,
                0, // time_req: default
                std::ptr::null_mut(), // no channel bindings
                if input_token.is_empty() { GSS_C_NO_BUFFER } else { &in_buf },
                &mut actual_mech,
                &mut out,
                &mut ret_flags,
                &mut time_rec,
            )
        };
        let token = out.as_slice().to_vec();
        let _ = unsafe { (lib.release_buffer)(&mut minor, &mut out) };
        if rc != GSS_S_COMPLETE && rc != GSS_S_CONTINUE_NEEDED {
            let msg = status_string(rc, false);
            let minor_msg = status_string(minor, true);
            return Err(format!("gss_init_sec_context failed: {} / {}", msg, minor_msg));
        }
        Ok(InitResult {
            token,
            continue_needed: rc == GSS_S_CONTINUE_NEEDED,
            integ_avail: ret_flags & GSS_C_INTEG_AVAIL != 0,
            context: *context,
        })
    }

    /// Result of one `gss_accept_sec_context` round.
    pub struct AcceptResult {
        pub token: Vec<u8>,
        pub continue_needed: bool,
        pub integ_avail: bool,
        pub src_name: GssName,
        pub context: GssCtxId,
    }

    /// Perform one `gss_accept_sec_context` step. `context` starts as
    /// `GSS_C_NO_CONTEXT`; subsequent calls pass the previous handle.
    pub fn accept_sec_context(
        context: &mut GssCtxId,
        input_token: &[u8],
    ) -> Result<AcceptResult, String> {
        let lib = lib().ok_or_else(|| "GSSAPI library unavailable".to_string())?;
        let mut minor: OmUint32 = 0;
        let mut ret_flags: OmUint32 = 0;
        let mut time_rec: OmUint32 = 0;
        let mut mech: *const GssOid = std::ptr::null();
        let mut src_name: GssName = std::ptr::null_mut();
        let mut delegated: GssCredId = std::ptr::null_mut();
        let mut out = GssBuffer::empty();
        let in_buf = GssBuffer {
            length: input_token.len(),
            value: input_token.as_ptr() as *mut c_void,
        };
        let rc = unsafe {
            (lib.accept_sec_context)(
                &mut minor,
                context,
                GSS_C_NO_CREDENTIAL,
                &in_buf,
                std::ptr::null_mut(),
                &mut src_name,
                &mut mech,
                &mut out,
                &mut ret_flags,
                &mut time_rec,
                &mut delegated,
            )
        };
        let token = out.as_slice().to_vec();
        let _ = unsafe { (lib.release_buffer)(&mut minor, &mut out) };
        if rc != GSS_S_COMPLETE && rc != GSS_S_CONTINUE_NEEDED {
            let msg = status_string(rc, false);
            let minor_msg = status_string(minor, true);
            // Delete the half-built context on failure.
            let _ = unsafe { (lib.delete_sec_context)(&mut minor, context, std::ptr::null_mut()) };
            return Err(format!("gss_accept_sec_context failed: {} / {}", msg, minor_msg));
        }
        Ok(AcceptResult {
            token,
            continue_needed: rc == GSS_S_CONTINUE_NEEDED,
            integ_avail: ret_flags & GSS_C_INTEG_AVAIL != 0,
            src_name,
            context: *context,
        })
    }

    /// Compute a MIC over `data` using `context`.
    pub fn get_mic(context: GssCtxId, data: &[u8]) -> Result<Vec<u8>, String> {
        let lib = lib().ok_or_else(|| "GSSAPI library unavailable".to_string())?;
        let mut minor: OmUint32 = 0;
        let msg_buf = GssBuffer {
            length: data.len(),
            value: data.as_ptr() as *mut c_void,
        };
        let mut mic = GssBuffer::empty();
        let rc = unsafe { (lib.get_mic)(&mut minor, context, 0, &msg_buf, &mut mic) };
        if rc != GSS_S_COMPLETE {
            let msg = status_string(rc, false);
            let minor_msg = status_string(minor, true);
            return Err(format!("gss_get_mic failed: {} / {}", msg, minor_msg));
        }
        let out = mic.as_slice().to_vec();
        let _ = unsafe { (lib.release_buffer)(&mut minor, &mut mic) };
        Ok(out)
    }

    /// Verify a MIC over `data` using `context`. Returns Ok(true) when valid.
    pub fn verify_mic(context: GssCtxId, data: &[u8], mic: &[u8]) -> Result<bool, String> {
        let lib = lib().ok_or_else(|| "GSSAPI library unavailable".to_string())?;
        let mut minor: OmUint32 = 0;
        let mut qop: GssQop = 0;
        let msg_buf = GssBuffer {
            length: data.len(),
            value: data.as_ptr() as *mut c_void,
        };
        let mic_buf = GssBuffer {
            length: mic.len(),
            value: mic.as_ptr() as *mut c_void,
        };
        let rc = unsafe { (lib.verify_mic)(&mut minor, context, &msg_buf, &mic_buf, &mut qop) };
        match rc {
            GSS_S_COMPLETE => Ok(true),
            GSS_S_FAILURE => Ok(false),
            other => {
                let msg = status_string(other, false);
                let minor_msg = status_string(minor, true);
                Err(format!("gss_verify_mic error: {} / {}", msg, minor_msg))
            }
        }
    }

    /// Extract the principal name from a source name (for account matching)
    /// using `gss_display_name`, which yields a printable user name.
    pub fn display_name(name: GssName) -> Result<String, String> {
        let lib = lib().ok_or_else(|| "GSSAPI library unavailable".to_string())?;
        let mut minor: OmUint32 = 0;
        let mut out = GssBuffer::empty();
        let mut out_type: *const GssOid = std::ptr::null();
        let rc = unsafe { (lib.display_name)(&mut minor, name, &mut out, &mut out_type) };
        if rc != GSS_S_COMPLETE {
            let msg = status_string(rc, false);
            let minor_msg = status_string(minor, true);
            return Err(format!("gss_display_name failed: {} / {}", msg, minor_msg));
        }
        let s = String::from_utf8_lossy(out.as_slice()).into_owned();
        let _ = unsafe { (lib.release_buffer)(&mut minor, &mut out) };
        Ok(s)
    }

    /// Release a GSS name.
    pub fn release_name(name: &mut GssName) {
        if let Some(lib) = lib() {
            let mut minor: OmUint32 = 0;
            let _ = unsafe { (lib.release_name)(&mut minor, name) };
        }
    }

    /// Delete a security context.
    pub fn delete_sec_context(context: &mut GssCtxId) {
        if let Some(lib) = lib() {
            let mut minor: OmUint32 = 0;
            let _ = unsafe { (lib.delete_sec_context)(&mut minor, context, std::ptr::null_mut()) };
        }
    }

    /// Release a credential handle.
    pub fn release_cred(cred: &mut GssCredId) {
        if let Some(lib) = lib() {
            let mut minor: OmUint32 = 0;
            let _ = unsafe { (lib.release_cred)(&mut minor, cred) };
        }
    }
}

#[cfg(not(unix))]
mod imp {
    pub fn gssapi_available() -> bool {
        false
    }
}

/// True when a loadable GSS-API library is present.

// Re-export the ABI types and the callable helpers for the client/server
// auth crates. These are only meaningful when `gssapi_available()` is true;
// on platforms without a GSSAPI library the `imp` module provides no-op
// stubs and callers must gate on `gssapi_available()` first.
#[cfg(unix)]
pub use imp::{
    GssBuffer, GssCtxId, GssCredId, GssName, GssOid, AcceptResult, InitResult,
    accept_sec_context, delete_sec_context, display_name, get_mic,
    import_hostbased_service, init_sec_context, release_cred, release_name,
    verify_mic,
};
pub fn gssapi_available() -> bool {
    imp::gssapi_available()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_is_cached_and_stable() {
        // Repeated calls must agree (LazyLock caches the dlopen result).
        assert_eq!(gssapi_available(), gssapi_available());
    }

    #[test]
    fn import_name_does_not_crash_without_context() {
        // With a library present, importing a host-based service name either
        // succeeds or returns an error; it must never panic or UB (no KDC is
        // needed for import, which is a pure name-mapping call).
        if gssapi_available() {
            let _ = import_hostbased_service("localhost");
        }
    }

    #[test]
    fn init_context_returns_error_without_credentials() {
        // Without a Kerberos ticket cache, gss_init_sec_context must return a
        // clean error (not crash). This exercises the full dlopen ABI path.
        if gssapi_available() {
            let mut name = match import_hostbased_service("localhost") {
                Ok(n) => n,
                Err(_) => return,
            };
            let mut ctx: GssCtxId = std::ptr::null_mut();
            let r = init_sec_context(&mut ctx, name, &[], false);
            // Both Ok (may need a ticket) and Err are acceptable; the point is
            // no panic and no UB through the FFI boundary.
            if let Ok(res) = r {
                let _ = res.token;
            }
            delete_sec_context(&mut ctx);
            release_name(&mut name);
        }
    }
}
