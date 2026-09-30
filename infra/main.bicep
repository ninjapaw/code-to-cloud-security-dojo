param labId string
param location string = resourceGroup().location
@minLength(7)
@maxLength(15)
param adminIpv4Address string
param registryName string
param vaultName string
param storageName string
param portalName string
param dojoName string
@minLength(71)
@maxLength(71)
param portalDigest string
@minLength(71)
@maxLength(71)
param dojoDigest string
param sourceRepository string
param sourceRevision string
param protection object
resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = { name: registryName }
resource vault 'Microsoft.KeyVault/vaults@2024-11-01' existing = { name: vaultName }
resource network 'Microsoft.Network/virtualNetworks@2024-05-01' existing = { name: '${labId}-vnet' }
resource integration 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = { parent: network, name: 'portal' }
resource endpoints 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = { parent: network, name: 'endpoints' }
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = { name: '${labId}-logs' }
module dojo 'modules/app.bicep' = {
  name: 'dojo-release'
  params: {
    name: dojoName
    location: location
    labId: labId
    image: '${registry.properties.loginServer}/dojo@${dojoDigest}'
    publicAccess: false
    adminIpv4Address: adminIpv4Address
    workspaceId: workspace.id
    port: '8080'
    settings: [
      { name: 'WEBGOAT_HOST', value: '${dojoName}.azurewebsites.net' }
      { name: 'WEBWOLF_HOST', value: 'localhost' }
    ]
  }
}
module dojoEndpoint 'modules/private-endpoint.bicep' = {
  name: 'dojo-endpoint'
  params: { name: '${dojoName}-pe', location: location, subnetId: endpoints.id, virtualNetworkId: network.id, targetId: dojo.outputs.id, groupId: 'sites', zoneName: 'privatelink.azurewebsites.net' }
}
module portal 'modules/app.bicep' = {
  name: 'portal-release'
  params: {
    name: portalName
    location: location
    labId: labId
    image: '${registry.properties.loginServer}/control-portal@${portalDigest}'
    publicAccess: true
    adminIpv4Address: adminIpv4Address
    workspaceId: workspace.id
    port: '8080'
    subnetId: integration.id
    settings: [
      { name: 'NODE_ENV', value: 'production' }
      { name: 'HOST', value: '0.0.0.0' }
      { name: 'PORT', value: '8080' }
      { name: 'DOJO_LAB_ID', value: labId }
      { name: 'DOJO_TENANT_ID', value: subscription().tenantId }
      { name: 'DOJO_SUBSCRIPTION_ID', value: subscription().subscriptionId }
      { name: 'DOJO_RESOURCE_GROUP', value: resourceGroup().name }
      { name: 'DOJO_LOCATION', value: location }
      { name: 'DOJO_ORIGIN', value: 'https://${portalName}.azurewebsites.net' }
      { name: 'DOJO_TARGET_HOST', value: dojo.outputs.hostName }
      { name: 'DOJO_STORAGE_NAME', value: storageName }
      { name: 'DOJO_SOURCE_REPOSITORY', value: sourceRepository }
      { name: 'DOJO_SOURCE_REVISION', value: sourceRevision }
      { name: 'DOJO_PROTECTION_CONFIG', value: string(protection) }
      { name: 'DOJO_IMAGE_DIGEST', value: dojoDigest }
      { name: 'DOJO_PORTAL_DIGEST', value: portalDigest }
      { name: 'DOJO_ADMIN_PASSWORD', value: '@Microsoft.KeyVault(SecretUri=${vault.properties.vaultUri}secrets/admin-password)' }
      { name: 'DOJO_SESSION_KEY', value: '@Microsoft.KeyVault(SecretUri=${vault.properties.vaultUri}secrets/session-key)' }
    ]
  }
}
output portalUrl string = 'https://${portal.outputs.hostName}'
output dojoResourceId string = dojo.outputs.id
