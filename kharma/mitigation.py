import psutil
import logging

class QuarantineManager:
    """
    Manages process-level mitigation by suspending and resuming processes.
    Used for proactive threat containment without permanent termination.
    """
    
    @staticmethod
    def suspend_process(pid):
        """Suspends a process given its PID."""
        try:
            p = psutil.Process(pid)
            p.suspend()
            logging.info(f"[MITIGATION] Process {pid} ({p.name()}) SUSPENDED.")
            return True
        except psutil.NoSuchProcess:
            return False
        except Exception as e:
            logging.error(f"[MITIGATION] Failed to suspend process {pid}: {e}")
            return False

    @staticmethod
    def resume_process(pid):
        """Resumes a suspended process given its PID."""
        try:
            p = psutil.Process(pid)
            p.resume()
            logging.info(f"[MITIGATION] Process {pid} ({p.name()}) RESUMED.")
            return True
        except psutil.NoSuchProcess:
            return False
        except Exception as e:
            logging.error(f"[MITIGATION] Failed to resume process {pid}: {e}")
            return False
