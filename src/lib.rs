
use std::ffi::{OsString};
use windows_service::{service::{ServiceAccess, ServiceState, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType}, service_manager::{ServiceManager, ServiceManagerAccess}};

use std::{
    thread::sleep,
    time::{Duration, Instant},
};
use windows_credential_manager_rs::CredentialManager;
use windows_service::Error::Winapi;
use windows_service::service::{ServiceExitCode, ServiceStatus};
use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;

#[derive(thiserror::Error, Debug)]
pub enum SecureLinkServiceError {
    #[error("Unauthorized")]
    UnauthorizedError,
    #[error("ServiceSpecificError, code: {0}")]
    ServiceSpecificError(u32),
    #[error("ServiceWin32Error, code: {0}")]
    ServiceWin32Error(u32),
    #[error("NotRunningAfterTimeoutError")]
    NotRunningAfterTimeoutError,
    #[error("NotStoppedAfterTimeoutError")]
    NotStoppedAfterTimeoutError,
    #[error("WindowsServiceApiError")]
    WindowsServiceApiError(Box<dyn std::error::Error>),
    #[error("CredentialManagerError")]
    CredentialManagerError(Box<dyn std::error::Error>),
    #[error("NetworkError")]
    NetworkError(Box<dyn std::error::Error>)
}

static SECURE_LINK_SERVICE_NAME: &str = "Secure Link Service";
static SECURE_LINK_SERVICE_AUTH_TOKEN_KEY: &str = "secure-link-service:auth-token-key";

pub fn install_service(exe_path: &str) -> Result<(), SecureLinkServiceError> {

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;

    let service_manager =
        ServiceManager::local_computer(None::<&str>, manager_access)
            .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

    let service_info = ServiceInfo {
        name: OsString::from(SECURE_LINK_SERVICE_NAME),
        display_name: OsString::from(SECURE_LINK_SERVICE_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path.into(),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // run as System
        account_password: None,
    };

    let service =
        service_manager
            .create_service(&service_info, ServiceAccess::CHANGE_CONFIG)
            .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

    println!("Service {} is installed.", SECURE_LINK_SERVICE_NAME);
    
    service.set_description("Secure Link Service")
        .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;
    Ok(())

}

pub fn uninstall_service() -> Result<(), SecureLinkServiceError> {
    
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager =
        ServiceManager::local_computer(None::<&str>, manager_access)
            .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = service_manager.open_service(SECURE_LINK_SERVICE_NAME, service_access)
        .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

    // The service will be marked for deletion as long as this function call succeeds.
    // However, it will not be deleted from the database until it is stopped and all open handles to it are closed.
    service.delete()
        .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;


    let status =
        service.query_status()
            .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

    // Our handle to it is not closed yet. So we can still query it.
    if status.current_state != ServiceState::Stopped {
        // If the service cannot be stopped, it will be deleted when the system restarts.
        service.stop()
            .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;
    }

    // Explicitly close our open handle to the service. This is automatically called when `service` goes out of scope.
    drop(service);

    // Win32 API does not give us a way to wait for service deletion.
    // To check if the service is deleted from the database, we have to poll it ourselves.
    let start = Instant::now();
    let timeout = Duration::from_secs(5);
    while start.elapsed() < timeout {
        if let Err(Winapi(e)) =
            service_manager.open_service(SECURE_LINK_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        {
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
                println!("{} is uninstalled.", SECURE_LINK_SERVICE_NAME);
                return Ok(());
            }
        }
        sleep(Duration::from_millis(100));
    }
    
    println!("{} is marked for deletion.", SECURE_LINK_SERVICE_NAME);

    Ok(())

}

pub fn start_service(
    secure_link_server_host: &str,
    secure_link_server_port: u16,
    auth_token: &str,
    service_log_file_path: &str,
) -> Result<(), SecureLinkServiceError> {
    
    let current_status = query_status()?;

    if current_status.current_state == ServiceState::Stopped {

        CredentialManager::store(SECURE_LINK_SERVICE_AUTH_TOKEN_KEY, auth_token)
            .map_err(|e| SecureLinkServiceError::CredentialManagerError(e))?;

        let manager_access = ServiceManagerAccess::CONNECT;

        let service_manager =
            ServiceManager::local_computer(None::<&str>, manager_access)
                .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

        let service_access = ServiceAccess::START;

        let service =
            service_manager.open_service(SECURE_LINK_SERVICE_NAME, service_access)
                .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

        let args: Vec<OsString> = vec![
            OsString::from(secure_link_server_host),
            OsString::from(format!("{}", secure_link_server_port)),
            OsString::from(service_log_file_path),
        ];

        service.start(&args)
            .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;
        
    }
    
    if poll_for_running_status(Duration::from_secs(5))? {
        Ok(())
    }else
    {   // If we exit the loop without returning, it means we timed out
        Err(SecureLinkServiceError::NotRunningAfterTimeoutError)
    }

}

pub fn stop_service() -> Result<(), SecureLinkServiceError> {


    let current_status = query_status()?;

    if current_status.current_state == ServiceState::Stopped {
        return Ok(())
    }


    let manager_access = ServiceManagerAccess::CONNECT;

    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)
        .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

    let service_access = ServiceAccess::STOP;

    let service =
        service_manager.open_service(SECURE_LINK_SERVICE_NAME, service_access)
            .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;
    
    service.stop()
        .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

    println!("Service {} stop sent.", SECURE_LINK_SERVICE_NAME);


    if poll_for_stopped_status(Duration::from_secs(5))? {
        Ok(())
    }else
    {
        Err(SecureLinkServiceError::NotStoppedAfterTimeoutError)
    }

}

pub fn is_service_installed() ->  Result<bool, SecureLinkServiceError> {
    
    let manager_access = ServiceManagerAccess::CONNECT;

    let service_manager =
        ServiceManager::local_computer(None::<&str>, manager_access)
            .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;
    
    let open_service_result =
        service_manager
            .open_service(SECURE_LINK_SERVICE_NAME, ServiceAccess::QUERY_CONFIG);
    
    match open_service_result {
        Ok(_service) => {
            Ok(true)
        }
        Err(err) => {
            
            match err {
                Winapi(winapi_error) => {

                    let os_error_code = 
                        winapi_error
                            .raw_os_error()
                            .ok_or(SecureLinkServiceError::WindowsServiceApiError("failed to get error code".into()))?;

                    if os_error_code == 1060 {
                        Ok(false)
                    }else
                    {
                        Err(SecureLinkServiceError::WindowsServiceApiError(Box::new(winapi_error)))
                    }
                    
                }
                
                err => Err(SecureLinkServiceError::WindowsServiceApiError(Box::new(err)))
            }
            
        }
    }
    
}

pub fn is_service_running() -> Result<bool, SecureLinkServiceError> {

    let status = query_status()?;

    let is_running =
        match status.current_state {
            ServiceState::StartPending => true,
            ServiceState::StopPending => true,
            ServiceState::Running => true,
            ServiceState::ContinuePending => true,
            ServiceState::PausePending => false,
            ServiceState::Paused => false,
            ServiceState::Stopped => false
     };
    
    Ok(is_running)

}

pub fn poll_for_running_status(timeout: Duration) -> Result<bool, SecureLinkServiceError> {

    let start = Instant::now();

    while start.elapsed() < timeout {

        let status = query_status()?;

        match status.current_state {
            ServiceState::Running => {
                println!("Service {} is started.", SECURE_LINK_SERVICE_NAME);
                return Ok(true);
            }

            ServiceState::Stopped => {
                return match status.exit_code {

                    ServiceExitCode::ServiceSpecific(5/*FAILED_UNAUTHORIZED*/) => {
                        Err(SecureLinkServiceError::UnauthorizedError)
                    }
                    ServiceExitCode::ServiceSpecific(code) => {
                        Err(SecureLinkServiceError::ServiceSpecificError(code))
                    }
                    ServiceExitCode::Win32(code) => {
                        Err(SecureLinkServiceError::ServiceWin32Error(code))
                    }

                }
            }

            _ => {}
        }

        sleep(Duration::from_millis(200));
    }

    Ok(false)

}

pub fn poll_for_stopped_status(timeout: Duration) -> Result<bool, SecureLinkServiceError> {

    let start = Instant::now();

    while start.elapsed() < timeout {

        let status = query_status()?;

        match status.current_state {
            ServiceState::Stopped => {
                return Ok(true);
            }
            _ => {}
        }

        sleep(Duration::from_millis(200));
    }

    Ok(false)

}

pub fn query_status() -> Result<ServiceStatus, SecureLinkServiceError> {

    let manager_access = ServiceManagerAccess::CONNECT;

    let service_manager =
        ServiceManager::local_computer(None::<&str>, manager_access)
            .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

    let service_access = ServiceAccess::QUERY_STATUS;

    let service =
        service_manager.open_service(SECURE_LINK_SERVICE_NAME, service_access)
            .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?;

    Ok(service.query_status()
        .map_err(|e| SecureLinkServiceError::WindowsServiceApiError(Box::new(e)))?)

}