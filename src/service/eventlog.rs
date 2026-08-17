//! Windows Application Event Log integration module.
//!
//! Emits structured diagnostic and lifecycle events to the Windows Application Log
//! (`eventvwr.msc` -> Windows Logs -> Application) under source `AgentControlSentry`.

#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[allow(dead_code)]
    pub const EVENTLOG_SUCCESS: u16 = 0x0000;
    pub const EVENTLOG_ERROR_TYPE: u16 = 0x0001;
    pub const EVENTLOG_WARNING_TYPE: u16 = 0x0002;
    pub const EVENTLOG_INFORMATION_TYPE: u16 = 0x0004;

    type HANDLE = *mut std::ffi::c_void;
    type BOOL = i32;
    type WORD = u16;
    type DWORD = u32;
    type LPCWSTR = *const u16;

    extern "system" {
        fn RegisterEventSourceW(lpUNCServerName: LPCWSTR, lpSourceName: LPCWSTR) -> HANDLE;
        fn DeregisterEventSource(hEventLog: HANDLE) -> BOOL;
        fn ReportEventW(
            hEventLog: HANDLE,
            wType: WORD,
            wCategory: WORD,
            dwEventID: DWORD,
            lpUserSid: *const std::ffi::c_void,
            wNumStrings: WORD,
            dwDataSize: DWORD,
            lpStrings: *const LPCWSTR,
            lpRawData: *const std::ffi::c_void,
        ) -> BOOL;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn write_event(level: u16, event_id: u32, message: &str) {
        unsafe {
            let source_name = to_wide("AgentControlSentry");
            let handle = RegisterEventSourceW(std::ptr::null(), source_name.as_ptr());
            if handle.is_null() {
                return;
            }

            let msg_wide = to_wide(message);
            let strings = [msg_wide.as_ptr()];

            let _ = ReportEventW(
                handle,
                level,
                0,
                event_id,
                std::ptr::null(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            );

            let _ = DeregisterEventSource(handle);
        }
    }
}

/// Log an informational event to Windows Event Viewer (Event ID 1000 series)
pub fn log_info(event_id: u32, message: &str) {
    #[cfg(windows)]
    imp::write_event(imp::EVENTLOG_INFORMATION_TYPE, event_id, message);
    #[cfg(not(windows))]
    let _ = (event_id, message);
}

/// Log a warning event to Windows Event Viewer (Event ID 2000 series)
pub fn log_warn(event_id: u32, message: &str) {
    #[cfg(windows)]
    imp::write_event(imp::EVENTLOG_WARNING_TYPE, event_id, message);
    #[cfg(not(windows))]
    let _ = (event_id, message);
}

/// Log an error event to Windows Event Viewer (Event ID 3000 series)
pub fn log_error(event_id: u32, message: &str) {
    #[cfg(windows)]
    imp::write_event(imp::EVENTLOG_ERROR_TYPE, event_id, message);
    #[cfg(not(windows))]
    let _ = (event_id, message);
}
