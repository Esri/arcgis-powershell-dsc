Configuration DeployWebApp
{
    param(
        [System.String]
        $NodeName = "localhost",
        
        [System.String]
        $WebAppName,
        
        [System.String]
        $SourceDir
    )

    Node $NodeName
    {
      if($Node.Thumbprint){
          LocalConfigurationManager
          {
              CertificateId = $Node.Thumbprint
          }
      }

        WindowsFeature IIS 
        { 
          Ensure = "Present"
          Name = "Web-Server"
        } 

        WindowsFeature ASP 
        { 
          Ensure = "Present"
          Name = "Web-Asp-Net45"
        } 

        Archive UnzipWebApp 
        {
            Destination = "C:\inetpub\wwwroot\$WebAppName"
            Path = $SourceDir
            Ensure = "Present"
            Force = $true
        }
    }
}