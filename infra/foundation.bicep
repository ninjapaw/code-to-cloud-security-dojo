param labId string
param location string = resourceGroup().location
@minLength(7)
@maxLength(15)
param adminIpv4Address string
param operatorObjectId string
@allowed(['User', 'ServicePrincipal'])
param operatorPrincipalType string = 'User'
@allowed(['B2', 'B3', 'P1v3'])
param appServiceSku string = 'B2'
param registryName string
param vaultName string
@description('Allow public Key Vault connections. Entra RBAC is always required.')
param keyVaultPublicAccess bool = true
@description('Restrict an enabled public vault endpoint to adminIpv4Address/32.')
param keyVaultRestrictToAdminIp bool = false
@description('Vault-only policy tags for public access. Use an empty object when no exception is required.')
param keyVaultPublicAccessTags object = { SecurityControl: 'Ignore' }
param storageName string
@description('Allow admin-IP-restricted public evidence access. Set false to require Private Link and publish through the portal or an authorized private-network runner.')
param evidencePublicAccess bool = true
param portalName string
param dojoName string
param nginxProxyEnabled bool = false
param nginxProxyName string = '${replace(dojoName, '-app', '')}-proxy'
var tags = { 'dojo.labId': labId, 'dojo.managedBy': 'code-to-cloud-security-dojo' }
var appNames = concat([portalName, dojoName], nginxProxyEnabled ? [nginxProxyName] : [])
var workloadNames = concat([dojoName], nginxProxyEnabled ? [nginxProxyName] : [])
resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' = {
  name: registryName
  location: location
  tags: tags
  sku: { name: 'Basic' }
  properties: { adminUserEnabled: false, anonymousPullEnabled: false, publicNetworkAccess: 'Enabled' }
}
resource portalIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: '${portalName}-identity'
}
resource workloadIdentities 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = [for name in workloadNames: {
  name: '${name}-identity'
  location: location
  tags: tags
}]
resource portalPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, portalName, 'AcrPull')
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalId: portalIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource workloadPulls 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (name, index) in workloadNames: {
  name: guid(registry.id, name, 'AcrPull')
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalId: workloadIdentities[index].properties.principalId
    principalType: 'ServicePrincipal'
  }
}]
resource plans 'Microsoft.Web/serverfarms@2024-11-01' = [for name in appNames: {
  name: '${name}-plan'
  location: location
  tags: tags
  kind: 'linux'
  sku: { name: appServiceSku, capacity: 1 }
  properties: { reserved: true }
}]
resource workloadNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${labId}-workloads-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'DenyInternetOutbound'
        properties: {
          priority: 200
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'Internet'
        }
      }
    ]
  }
}
resource network 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  
  name: '${labId}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['10.87.0.0/16'] }
    subnets: [
      { name: 'portal', properties: { addressPrefix: '10.87.1.0/24', delegations: [{ name: 'web', properties: { serviceName: 'Microsoft.Web/serverFarms' } }] } }
      { name: 'endpoints', properties: { addressPrefix: '10.87.2.0/24', privateEndpointNetworkPolicies: 'Disabled' } }
      {
        name: 'workloads'
        properties: {
          addressPrefix: '10.87.3.0/24'
          delegations: [{ name: 'web', properties: { serviceName: 'Microsoft.Web/serverFarms' } }]
          networkSecurityGroup: { id: workloadNsg.id }
        }
      }
    ]
  }
}
resource vault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: vaultName
  location: location
  // Apply policy tags only to a public vault, without overriding lab ownership.
  tags: union(keyVaultPublicAccess ? keyVaultPublicAccessTags : {}, tags)
  properties: {
    tenantId: subscription().tenantId
    sku: { name: 'standard', family: 'A' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: keyVaultPublicAccess ? 'Enabled' : 'Disabled'
    networkAcls: {
      defaultAction: keyVaultPublicAccess && !keyVaultRestrictToAdminIp ? 'Allow' : 'Deny'
      bypass: 'None'
      ipRules: keyVaultPublicAccess && keyVaultRestrictToAdminIp ? [{ value: '${adminIpv4Address}/32' }] : []
    }
  }
}
resource vaultRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for grant in [
  { portal: true, role: '4633458b-17de-408a-b874-0445c86b69e6', kind: 'ServicePrincipal' }
  { portal: false, role: 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7', kind: operatorPrincipalType }
]: {
  name: guid(vault.id, grant.portal ? portalIdentity.id : operatorObjectId, grant.role)
  scope: vault
  properties: { principalId: grant.portal ? portalIdentity.properties.principalId : operatorObjectId, principalType: grant.kind, roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', grant.role) }
}]
resource storage 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: storageName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: evidencePublicAccess ? 'Enabled' : 'Disabled'
    networkAcls: { defaultAction: 'Deny', bypass: 'None', ipRules: [{ value: adminIpv4Address, action: 'Allow' }] }
  }
}
resource blob 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' = {
  parent: storage
  name: 'default'
  properties: { isVersioningEnabled: true, deleteRetentionPolicy: { enabled: true, days: 7 } }
}
resource evidence 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = {
  parent: blob
  name: 'evidence'
  properties: { publicAccess: 'None' }
}
resource evidenceRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for grant in [
  { portal: true, kind: 'ServicePrincipal' }
  { portal: false, kind: operatorPrincipalType }
]: {
  name: guid(evidence.id, grant.portal ? portalIdentity.id : operatorObjectId, 'blob-data-contributor')
  scope: evidence
  properties: {
    principalId: grant.portal ? portalIdentity.properties.principalId : operatorObjectId
    principalType: grant.kind
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  }
}]
module vaultEndpoint 'modules/private-endpoint.bicep' = {
  name: 'vault-endpoint'
  params: { name: '${vaultName}-pe', location: location, subnetId: network.properties.subnets[1].id, virtualNetworkId: network.id, targetId: vault.id, groupId: 'vault', zoneName: 'privatelink.vaultcore.azure.net' }
}
module blobEndpoint 'modules/private-endpoint.bicep' = {
  name: 'blob-endpoint'
  params: { name: '${storageName}-pe', location: location, subnetId: network.properties.subnets[1].id, virtualNetworkId: network.id, targetId: storage.id, groupId: 'blob', zoneName: 'privatelink.blob.${environment().suffixes.storage}' }
}
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${labId}-logs'
  location: location
  tags: tags
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 30 }
}
resource portalReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, portalIdentity.id, 'dojo-reader')
  properties: {
    principalId: portalIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')
  }
}
output portalPrincipalId string = portalIdentity.properties.principalId
output registryLoginServer string = registry.properties.loginServer
output vaultUri string = vault.properties.vaultUri
output evidenceEndpoint string = storage.properties.primaryEndpoints.blob
