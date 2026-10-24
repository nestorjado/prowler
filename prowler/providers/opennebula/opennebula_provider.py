import pyone  
from configparser import ConfigParser
from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.opennebula.models import (
    OpennebulaSession,
    OpennebulaIdentity,
    OpennebulaOutputOptions
)
from prowler.providers.opennebula.exceptions.exceptions import OpennebulaError, OpennebulaCredentialsError
from prowler.providers.opennebula.lib.mutelist.mutelist import OpennebulaMutelist
from colorama import Fore

class OpennebulaProvider(Provider):
    _type: str = "opennebula"
    _identity: OpennebulaIdentity
    _session: OpennebulaSession
    _audit_config: dict
    _output_options: OpennebulaOutputOptions
    _mutelist: dict
    audit_metadata: Audit_Metadata

    def __init__(
        self, 
        credentials_file: str = None,
        config_file: str = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        """
        Initializes the OpennebulaProvider instance.
        Args:
            arguments (dict): A dictionary containing configuration arguments.
        """
        logger.info("Setting Opennebula provider...")
        
        # Set up the session
        self._session = self.setup_session(credentials_file)
        self.test_connection(self.session.client)
        
        # Set the identity
        self._identity = self.set_identity()
        
        # Set the output options
        self._output_options = OpennebulaOutputOptions(
            None,
            {},
            self.identity
        )
        
        # Set provider configuration
        if (config_file):
            self._audit_config = load_and_validate_config_file(
                self,
                config_file,
            )

        # Mutelist
        self._mutelist = OpennebulaMutelist(
            mutelist_path=mutelist_path or "",
            mutelist_content=mutelist_content or {},
        )

        Provider.set_global_provider(self)

    @property
    def identity(self):
        return self._identity

    @property
    def session(self):
        return self._session

    @property
    def type(self):
        return self._type

    @property
    def audit_config(self):
        return self._audit_config
        
    @property
    def output_options(self):
        return self._output_options

    @property
    def mutelist(self):
        return self._mutelist

    @staticmethod
    def setup_session(
        credentials_file: str = None
    ) -> OpennebulaSession:
        """
        Sets up the Opennebula session.
        
        Args:
            credentials_file (str): Path to the credentials file.
            
        Returns:
            OpennebulaSessionModel: Session credentials for Opennebula.
        """
        try:
            config = ConfigParser()
            config.read(credentials_file)
            endpoint = config.get('opennebula', 'endpoint')
            username = config.get('opennebula', 'username')
            auth_token = config.get('opennebula', 'auth_token')
            # Create Opennebula client
            client = pyone.OneServer(endpoint, f"{username}:{auth_token}")
            return OpennebulaSession(
                client=client,
                endpoint=endpoint,
                username=username,
                auth_token=auth_token
            )
        except Exception as e:
            raise OpennebulaCredentialsError(
                message=f"Error reading credentials file: {str(e)}"
            )

    def print_credentials(self):
        """Print the provider's credentials information."""
        credentials = [
            f"{k}: {Fore.YELLOW}{v}{Fore.RESET}" for k, v in self.identity.__dict__.items()
        ]
        print_boxes(credentials, "Opennebula Credentials")

    @staticmethod
    def test_connection(client: pyone.OneServer):
        """Test the connection to the Opennebula API."""
        try:
            client.system.version()
            logger.info("Connection to Opennebula API successful.")
        except Exception as e:
            logger.error("Connection to Opennebula API failed.")
            raise OpennebulaError(original_exception=e)
    
    def set_identity(self) -> OpennebulaIdentity:
        """Set the identity of the Opennebula provider."""
        identity = self.session.client.user.info(-1),
        user_id = identity[0].get_ID()
        user_name = identity[0].get_NAME()
        group_id = identity[0].get_GID()
        group_name = identity[0].get_GNAME()
        return OpennebulaIdentity(
            user_id=user_id,
            user_name=user_name,
            group_id=group_id,
            group_name=group_name
        ) 

    # --- Contrato de proveedor dinamico (Prowler >= 5.4x): sustituye los 'elif' del nucleo ---
    sdk_only = True  # solo CLI/SDK; no se expone en la Prowler App (API/UI)

    @classmethod
    def from_cli_args(cls, arguments, fixer_config):
        return cls(
            credentials_file=getattr(arguments, "credentials_file", None),
            config_file=getattr(arguments, "config_file", None),
            mutelist_path=getattr(arguments, "mutelist_file", None),
        )

    def get_output_options(self, arguments, bulk_checks_metadata):
        return OpennebulaOutputOptions(arguments, bulk_checks_metadata, self.identity)

    def get_stdout_detail(self, finding) -> str:
        return getattr(finding, "location", "") or "global"

    def get_summary_entity(self) -> tuple:
        return ("OpenNebula user", self.identity.user_name)

    def get_finding_output_data(self, check_output) -> dict:
        return {
            "auth_method": "core",
            "account_uid": self.identity.user_id,
            "account_name": self.identity.user_name,
            "resource_name": check_output.resource_name,
            "resource_uid": check_output.resource_id,
            "region": "global",
        }

    def get_html_assessment_summary(self) -> str:
        return (
            '<div class="col-md-2"><div class="card"><div class="card-header">'
            "OpenNebula Assessment Summary</div>"
            '<ul class="list-group list-group-flush"><li class="list-group-item">'
            f"<b>User:</b> {self.identity.user_name} (ID {self.identity.user_id})"
            "</li></ul></div></div>"
        )
