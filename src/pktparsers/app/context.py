"""
Application context: configuration, cache, log directories.
"""

import os
import pwd
from pathlib import Path
from logging import getLogger

logger = getLogger(__name__)

class AppContext:
    """
    Manages application directories and configuration.
    
    Attributes:
        real_user: actual user (respects SUDO_USER)
        home_dir: user's home directory
        config_dir: ~/.config/pktparsers
        cache_dir: ~/.cache/pktparsers
        log_file: path to main log file
    """
    
    def __init__(self, config: dict = None, log_file: Path = None):
        self.config = config or {}
        
        # Determine real user (handle sudo)
        self.real_user = os.environ.get("SUDO_USER") or os.getlogin()
        pw = pwd.getpwnam(self.real_user)
        self.home_dir = Path(pw.pw_dir)
        
        # Setup dirs
        self.config_dir = self.home_dir / ".config" / "pktparsers"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.chmod(0o740)
        
        self.cache_dir = self.home_dir / ".cache" / "pktparsers"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.chmod(0o740)
        
        self.log_file = log_file or (self.cache_dir / "pktparsers.log")
        
        logger.debug(
            f"AppContext initialized — user={self.real_user}, "
            f"config_dir={self.config_dir}, log_file={self.log_file}"
        )

    def get_config_file(self, name: str) -> Path:
        """Get path to config file"""
        return self.config_dir / name

    def get_cache_file(self, name: str) -> Path:
        """Get path to cache file"""
        return self.cache_dir / name
