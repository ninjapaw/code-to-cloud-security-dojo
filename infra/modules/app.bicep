param name string
param location string
param labId string
param image string
param publicAccess bool
param restrictToAdminIp bool = true
param adminIpv4Address string
param port string
param workspaceId string
param subnetId string = ''
param settings { name: string, value: string }[] = []
param healthCheckPath string = publicAccess ? '/health' : '/WebGoat/actuator/health'
param evidenceTags object = {}
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = { name: '${name}-identity' }
resource plan 'Microsoft.Web/serverfarms@2024-11-01' existing = { name: '${name}-plan' }
resource app 'Microsoft.Web/sites@2024-11-01' = {
  name: name
  location: location
  tags: union(evidenceTags, { 'dojo.labId': labId, 'dojo.managedBy': 'code-to-cloud-security-dojo' })
  kind: 'app,linux,container'
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identity.id}': {} } }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: publicAccess ? 'Enabled' : 'Disabled'
    virtualNetworkSubnetId: empty(subnetId) ? null : subnetId
    outboundVnetRouting: { applicationTraffic: !empty(subnetId) }
    keyVaultReferenceIdentity: identity.id
    siteConfig: {
      linuxFxVersion: 'DOCKER|${image}'
      acrUseManagedIdentityCreds: true
      acrUserManagedIdentityID: identity.properties.clientId
      alwaysOn: true
      healthCheckPath: healthCheckPath
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      ipSecurityRestrictionsDefaultAction: publicAccess && !restrictToAdminIp ? 'Allow' : 'Deny'
      scmIpSecurityRestrictionsDefaultAction: 'Deny'
      scmIpSecurityRestrictionsUseMain: false
      scmIpSecurityRestrictions: []
      ipSecurityRestrictions: publicAccess && restrictToAdminIp ? [{ name: 'AuthorizedAdmin', ipAddress: '${adminIpv4Address}/32', action: 'Allow', priority: 100 }] : []
      appSettings: concat([
        { name: 'WEBSITES_PORT', value: port }
        { name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE', value: 'false' }
        { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId }
      ], settings)
    }
  }
}
resource ftpPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-11-01' = {
  parent: app
  name: 'ftp'
  properties: { allow: false }
}
resource scmPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-11-01' = {
  parent: app
  name: 'scm'
  properties: { allow: false }
}
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: app
  name: 'lab-evidence'
  properties: {
    workspaceId: workspaceId
    logs: [{ category: 'AppServiceHTTPLogs', enabled: true }, { category: 'AppServiceConsoleLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}
output id string = app.id
output hostName string = app.properties.defaultHostName
