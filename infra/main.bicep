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
@description('Allow public connections to the deliberately vulnerable WebGoat training website.')
param dojoPublicAccess bool = true
@description('Restrict an enabled public WebGoat endpoint to adminIpv4Address/32.')
param dojoRestrictToAdminIp bool = false
@minLength(71)
@maxLength(71)
param portalDigest string
@minLength(71)
@maxLength(71)
param dojoDigest string
param sourceRepository string
param sourceRevision string
param protection object
param drowsyDragonEnabled bool = false
param drowsyDragonName string = '${replace(dojoName, '-app', '')}-dragon'
@maxLength(71)
param drowsyDragonDigest string = ''
@maxLength(64)
param drowsyDragonScanHash string = ''
param nginxProxyEnabled bool = false
param nginxProxyName string = '${replace(dojoName, '-app', '')}-proxy'
@allowed(['vulnerable', 'remediated'])
param nginxProxyMode string = 'vulnerable'
@maxLength(71)
param nginxProxyDigest string = ''
@maxLength(64)
param nginxProxyScanHash string = ''
resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = { name: registryName }
resource vault 'Microsoft.KeyVault/vaults@2024-11-01' existing = { name: vaultName }
resource network 'Microsoft.Network/virtualNetworks@2024-05-01' existing = { name: '${labId}-vnet' }
resource integration 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = { parent: network, name: 'portal' }
resource endpoints 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = { parent: network, name: 'endpoints' }
resource workloads 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = { parent: network, name: 'workloads' }
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = { name: '${labId}-logs' }
module drowsyDragon 'modules/drowsy-dragon.bicep' = if (drowsyDragonEnabled) {
  name: 'drowsy-dragon-release'
  params: {
    name: drowsyDragonName
    location: location
    labId: labId
    registryName: registryName
    imageDigest: drowsyDragonDigest
    scanHash: drowsyDragonScanHash
  }
}
module dojo 'modules/app.bicep' = {
  name: 'dojo-release'
  params: {
    name: dojoName
    location: location
    labId: labId
    image: '${registry.properties.loginServer}/${dojoName}@${dojoDigest}'
    publicAccess: dojoPublicAccess
    restrictToAdminIp: dojoRestrictToAdminIp
    adminIpv4Address: adminIpv4Address
    workspaceId: workspace.id
    port: '8080'
    subnetId: workloads.id
    healthCheckPath: '/WebGoat/actuator/health'
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
    image: '${registry.properties.loginServer}/${portalName}@${portalDigest}'
    publicAccess: true
    restrictToAdminIp: true
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
      { name: 'DOJO_DROWSY_DRAGON_ENABLED', value: drowsyDragonEnabled ? 'true' : 'false' }
      { name: 'DOJO_DROWSY_DRAGON_DIGEST', value: drowsyDragonDigest }
      { name: 'DOJO_NGINX_PROXY_ENABLED', value: nginxProxyEnabled ? 'true' : 'false' }
      { name: 'DOJO_NGINX_PROXY_MODE', value: nginxProxyMode }
      { name: 'DOJO_NGINX_PROXY_DIGEST', value: nginxProxyDigest }
      { name: 'DOJO_ADMIN_USERNAME', value: '@Microsoft.KeyVault(SecretUri=${vault.properties.vaultUri}secrets/admin-username)' }
      { name: 'DOJO_ADMIN_PASSWORD', value: '@Microsoft.KeyVault(SecretUri=${vault.properties.vaultUri}secrets/admin-password)' }
      { name: 'DOJO_SESSION_KEY', value: '@Microsoft.KeyVault(SecretUri=${vault.properties.vaultUri}secrets/session-key)' }
    ]
  }
}
module nginxProxy 'modules/app.bicep' = if (nginxProxyEnabled) {
  name: 'nginx-proxy-release'
  params: {
    name: nginxProxyName
    location: location
    labId: labId
    image: '${registry.properties.loginServer}/${nginxProxyName}@${nginxProxyDigest}'
    publicAccess: false
    adminIpv4Address: adminIpv4Address
    workspaceId: workspace.id
    port: '80'
    subnetId: workloads.id
    healthCheckPath: '/health'
    evidenceTags: {
      'dojo.demo': 'nginx-proxy'
      'dojo.mode': nginxProxyMode
      'dojo.scanHash': nginxProxyScanHash
    }
    settings: [
      { name: 'PORT', value: '3000' }
      { name: 'DEFENDER_ENABLED', value: 'true' }
      { name: 'DEFENDER_APPSERVICES_TIER', value: protection.AppServices.pricingTier }
      { name: 'DEFENDER_CONTAINERS_TIER', value: protection.Containers.pricingTier }
      { name: 'DEFENDER_CSPM_TIER', value: protection.CloudPosture.pricingTier }
      { name: 'DEFENDER_REGISTRY_ASSESSMENT', value: 'true' }
    ]
  }
}
module nginxProxyEndpoint 'modules/private-endpoint.bicep' = if (nginxProxyEnabled) {
  name: 'nginx-proxy-endpoint'
  params: {
    name: '${nginxProxyName}-pe'
    location: location
    subnetId: endpoints.id
    virtualNetworkId: network.id
    targetId: nginxProxy!.outputs.id
    groupId: 'sites'
    zoneName: 'privatelink.azurewebsites.net'
    zoneLinkName: '${dojoName}-pe-link'
  }
  dependsOn: [dojoEndpoint]
}
output portalUrl string = 'https://${portal.outputs.hostName}'
output dojoUrl string = 'https://${dojo.outputs.hostName}/WebGoat/'
output dojoResourceId string = dojo.outputs.id
