namespace WtxPcCheck.Services;

public sealed class ScanPauseController : IDisposable
{
    private readonly ManualResetEventSlim _resumeEvent = new(true);
    private int _paused;

    public bool IsPaused => Volatile.Read(ref _paused) != 0;

    public void Pause()
    {
        if (Interlocked.Exchange(ref _paused, 1) == 0)
            _resumeEvent.Reset();
    }

    public void Resume()
    {
        if (Interlocked.Exchange(ref _paused, 0) != 0)
            _resumeEvent.Set();
    }

    public void WaitIfPaused(CancellationToken cancellationToken)
    {
        if (!IsPaused) return;
        _resumeEvent.Wait(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
    }

    public void Dispose() => _resumeEvent.Dispose();
}
