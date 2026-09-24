use std::time::Duration;
use tokio::io::AsyncReadExt;

pub async fn check_stability<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    hold_duration: Duration,
) -> bool {
    let mut buf = [0u8; 1];
    let read_fut = stream.read(&mut buf);
    match tokio::time::timeout(hold_duration, read_fut).await {
        Ok(Ok(0)) => false,  // EOF -> connection terminated
        Ok(Ok(_)) => true,   // Server sent data
        Ok(Err(_)) => false, // Connection reset / dropped
        Err(_) => true,      // Timed out -> connection held successfully
    }
}
