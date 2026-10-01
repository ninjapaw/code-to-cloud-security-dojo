param labId string
param location string = resourceGroup().location
param portalName string
@allowed(['B2', 'B3', 'P1v3'])
param appServiceSku string
param registryName string
param vaultName string
@minLength(71)
@maxLength(71)
param imageDigest string
param runId string

var name = '${portalName}-bootstrap'
var tags = { 'dojo.labId': labId, 'dojo.managedBy': 'code-to-cloud-security-dojo' }
resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = { name: registryName }
resource vault 'Microsoft.KeyVault/vaults@2024-11-01' existing = { name: vaultName }
resource plan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: '${portalName}-plan'
  location: location
  tags: tags
  kind: 'linux'
  sku: { name: appServiceSku, capacity: 1 }
  properties: { reserved: true }
}
resource network 'Microsoft.Network/virtualNetworks@2024-05-01' existing = { name: '${labId}-vnet' }
resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = { parent: network, name: 'portal' }
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = { name: '${labId}-logs' }
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: '${name}-identity'
  location: location
  tags: tags
}
resource pull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identity.id, 'AcrPull')
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource writeSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, identity.id, 'KeyVaultSecretsOfficer')
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource worker 'Microsoft.Web/sites@2024-11-01' = {
  name: name
  location: location
  tags: tags
  kind: 'app,linux,container'
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identity.id}': {} } }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: 'Disabled'
    virtualNetworkSubnetId: subnet.id
    siteConfig: {
      vnetRouteAllEnabled: true
      linuxFxVersion: 'DOCKER|${registry.properties.loginServer}/secret-bootstrap@${imageDigest}'
      acrUseManagedIdentityCreds: true
      acrUserManagedIdentityID: identity.properties.clientId
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      ipSecurityRestrictionsDefaultAction: 'Deny'
      scmIpSecurityRestrictionsDefaultAction: 'Deny'
      appSettings: [
        { name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE', value: 'false' }
        { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId }
        { name: 'DOJO_BOOTSTRAP_VAULT', value: vaultName }
        { name: 'DOJO_BOOTSTRAP_RUN_ID', value: runId }
      ]
    }
  }
  dependsOn: [pull, writeSecrets]
}
resource ftpPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-11-01' = {
  parent: worker
  name: 'ftp'
  properties: { allow: false }
}
resource scmPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-11-01' = {
  parent: worker
  name: 'scm'
  properties: { allow: false }
}
resource logs 'Microsoft.Web/sites/config@2024-11-01' = {
  parent: worker
  name: 'logs'
  properties: { applicationLogs: { fileSystem: { level: 'Information' } } }
}
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: worker
  name: 'bootstrap-status'
  properties: {
    workspaceId: workspace.id
    logs: [{ category: 'AppServiceConsoleLogs', enabled: true }]
  }
}
output workerId string = worker.id
output identityId string = identity.id
output pullId string = pull.id
output writeSecretsId string = writeSecrets.id
