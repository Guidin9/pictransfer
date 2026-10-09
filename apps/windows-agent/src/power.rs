//! Power and memory discipline (resource-budget.md §2.7–2.8): EcoQoS while idle,
//! normal QoS during work, and a working-set trim after work.

use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
    PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
    ProcessPowerThrottling, SetProcessInformation, SetProcessWorkingSetSize,
};

/// Turns EcoQoS (execution-speed throttling) on or off for this process.
/// Returns `false` if the OS refused (e.g. older Windows); callers may ignore it.
pub fn set_eco_qos(on: bool) -> bool {
    let state = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        StateMask: if on {
            PROCESS_POWER_THROTTLING_EXECUTION_SPEED
        } else {
            0
        },
    };
    let size = u32::try_from(std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>()).unwrap_or(0);
    // SAFETY: a correctly sized PROCESS_POWER_THROTTLING_STATE for ProcessPowerThrottling,
    // on the pseudo-handle of the current process.
    unsafe {
        SetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            (&raw const state).cast(),
            size,
        ) != 0
    }
}

/// Releases this process's working set back to the OS (pages fault back in on use).
pub fn trim_working_set() -> bool {
    // SAFETY: (usize::MAX, usize::MAX) is the documented "trim" request for the current process.
    unsafe { SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX) != 0 }
}

#[cfg(test)]
mod tests {
    #[test]
    fn eco_qos_toggles_and_trim_succeeds() {
        assert!(super::set_eco_qos(true));
        assert!(super::set_eco_qos(false));
        assert!(super::trim_working_set());
    }
}
