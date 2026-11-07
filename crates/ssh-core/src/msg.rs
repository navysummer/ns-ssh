pub const SSH_MSG_DISCONNECT: u8 = 1;
pub const SSH_MSG_IGNORE: u8 = 2;
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
pub const SSH_MSG_DEBUG: u8 = 4;
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
pub const SSH_MSG_EXT_INFO: u8 = 7;
pub const SSH_MSG_NEWCOMPRESS: u8 = 8;

pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_NEWKEYS: u8 = 21;

pub const SSH_MSG_KEXDH_INIT: u8 = 30;
pub const SSH_MSG_KEXDH_REPLY: u8 = 31;
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

pub const SSH_MSG_KEX_DH_GEX_REQUEST_OLD: u8 = 30;
pub const SSH_MSG_KEX_DH_GEX_GROUP: u8 = 31;
pub const SSH_MSG_KEX_DH_GEX_INIT: u8 = 32;
pub const SSH_MSG_KEX_DH_GEX_REPLY: u8 = 33;
pub const SSH_MSG_KEX_DH_GEX_REQUEST: u8 = 34;

pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
pub const SSH_MSG_USERAUTH_PK_OK: u8 = 60;
pub const SSH_MSG_USERAUTH_INFO_REQUEST: u8 = 60;
pub const SSH_MSG_USERAUTH_INFO_RESPONSE: u8 = 61;
// GSSAPI user auth (RFC 4462 §6): 60-66, used in the gssapi-with-mic method
// context. Note 60/61 overlap PK_OK/INFO_REQUEST/INFO_RESPONSE (disambiguated
// by the auth method in progress); 62 is unused.
pub const SSH_MSG_USERAUTH_GSSAPI_RESPONSE: u8 = 60;
pub const SSH_MSG_USERAUTH_GSSAPI_TOKEN: u8 = 61;
pub const SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE: u8 = 63;
pub const SSH_MSG_USERAUTH_GSSAPI_ERROR: u8 = 64;
pub const SSH_MSG_USERAUTH_GSSAPI_ERRTOK: u8 = 65;
pub const SSH_MSG_USERAUTH_GSSAPI_MIC: u8 = 66;

pub const SSH_AUTH_METHOD_GSSAPI_WITH_MIC: &str = "gssapi-with-mic";

pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;

pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

pub const SSH_EXT_INFO_C: u8 = 7;
pub const SSH_EXT_INFO_S: u8 = 7;

pub const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: u32 = 1;
pub const SSH_DISCONNECT_PROTOCOL_ERROR: u32 = 2;
pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;
pub const SSH_DISCONNECT_HOST_AUTHENTICATION_FAILURE: u32 = 4;
pub const SSH_DISCONNECT_TOO_MANY_CONNECTIONS: u32 = 5;
pub const SSH_DISCONNECT_NO_AUTH: u32 = 6;
pub const SSH_DISCONNECT_AUTHENTICATION_FAILURE: u32 = 7;
pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 8;
pub const SSH_DISCONNECT_ILLEGAL_USER_NAME: u32 = 9;
pub const SSH_DISCONNECT_BY_APPLICATION: u32 = 11;

pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
pub const SSH_OPEN_CONNECT_FAILED: u32 = 2;
pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
pub const SSH_OPEN_RESOURCE_SHORTAGE: u32 = 4;

pub const CHANNEL_EXTENDED_DATA_TYPE_STDERR: u32 = 1;

pub const CHANNEL_PACKET_WINDOW_SIZE: u32 = 2097152;
pub const CHANNEL_MAX_PACKET_SIZE: u32 = 32768;

pub const SSH_SERVICE_NAME_USERAUTH: &str = "ssh-userauth";
pub const SSH_SERVICE_NAME_CONNECTION: &str = "ssh-connection";

pub const SSH_CHANNEL_TYPE_SESSION: &str = "session";
pub const SSH_CHANNEL_TYPE_DIRECT_TCPIP: &str = "direct-tcpip";
pub const SSH_CHANNEL_TYPE_FORWARDED_TCPIP: &str = "forwarded-tcpip";
pub const SSH_CHANNEL_TYPE_AUTH_AGENT: &str = "auth-agent@openssh.com";
pub const SSH_CHANNEL_TYPE_AUTH_AGENT_IDENTITY: &str = "auth-agent-req@openssh.com";
pub const SSH_CHANNEL_TYPE_X11: &str = "x11";
pub const SSH_CHANNEL_TYPE_DIRECT_STREAMLOCAL: &str = "direct-streamlocal@openssh.com";
pub const SSH_CHANNEL_TYPE_FORWARDED_STREAMLOCAL: &str = "forwarded-streamlocal@openssh.com";
pub const SSH_CHANNEL_TYPE_TUN: &str = "tun@openssh.com";

pub const SSH_GLOBAL_REQUEST_TCPIP_FORWARD: &str = "tcpip-forward";
pub const SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD: &str = "cancel-tcpip-forward";
pub const SSH_GLOBAL_REQUEST_STREAMLOCAL_FORWARD: &str = "streamlocal-forward@openssh.com";
pub const SSH_GLOBAL_REQUEST_CANCEL_STREAMLOCAL_FORWARD: &str = "cancel-streamlocal-forward@openssh.com";
pub const SSH_GLOBAL_REQUEST_NO_MORE_SESSIONS: &str = "no-more-sessions@openssh.com";
pub const SSH_GLOBAL_REQUEST_HOSTKEYS_PROVE: &str = "hostkeys-prove-00@openssh.com";
pub const SSH_GLOBAL_REQUEST_KEEPALIVE: &str = "keepalive@openssh.com";

pub const SSH_REQUEST_PTY: &str = "pty-req";
pub const SSH_REQUEST_SHELL: &str = "shell";
pub const SSH_REQUEST_EXEC: &str = "exec";
pub const SSH_REQUEST_ENV: &str = "env";
pub const SSH_REQUEST_SUBSYSTEM: &str = "subsystem";
pub const SSH_REQUEST_WINDOW_CHANGE: &str = "window-change";
pub const SSH_REQUEST_SIGNAL: &str = "signal";
pub const SSH_REQUEST_EXIT_STATUS: &str = "exit-status";
pub const SSH_REQUEST_EXIT_SIGNAL: &str = "exit-signal";
pub const SSH_REQUEST_X11: &str = "x11-req";
pub const SSH_REQUEST_AUTH_AGENT: &str = "auth-agent-req@openssh.com";

pub const SSH_EXT_SERVER_SIG_ALGS: &str = "server-sig-algs";
pub const SSH_EXT_GLOBAL_REQUESTS_OK: &str = "global-requests-ok";

pub const SSH_VERSION: &str = "SSH-2.0-ns-ssh_1.0";
pub const SSH_SERVER_VERSION: &str = "SSH-2.0-ns-ssh-server_1.0";
