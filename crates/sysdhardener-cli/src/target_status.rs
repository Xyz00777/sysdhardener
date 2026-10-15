use sysdhardener_observer::TargetStatus;

pub fn report(status: TargetStatus) {
    let (label, exit_code, signal, abnormal) = match status {
        TargetStatus::Exited(code) => ("exited", code, 0, code != 0),
        TargetStatus::Signaled(signal) => ("signaled", 0, signal, true),
        TargetStatus::Unknown => ("unknown", 0, 0, false),
    };
    tracing::info!(target: "sysdhardener.cli", target_status = label, target_exit_code = exit_code, target_signal = signal, "target process outcome");
    if abnormal {
        tracing::warn!(target: "sysdhardener.cli", target_status = label, target_exit_code = exit_code, target_signal = signal, "target process completed abnormally");
    }
}
