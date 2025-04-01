import uvicorn # type: ignore
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more verbose output
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    try:
        logger.info("Starting security scanner server...")
        logger.debug("Server configuration: host=127.0.0.1, port=8080")
        uvicorn.run(
            "security_scanner:app",
            host="127.0.0.1",
            port=8080,  # Changed to port 8080
            reload=True,
            log_level="debug"  # Changed to debug for more verbose output
        )
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        logger.debug(f"Exception details: {repr(e)}")
        sys.exit(1) 