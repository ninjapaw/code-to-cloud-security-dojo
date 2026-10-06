param name string
param location string
param labId string
param registryName string
@minLength(71)
@maxLength(71)
param imageDigest string
@minLength(64)
@maxLength(64)
param scanHash string

var tags = {
  'dojo.labId': labId
  'dojo.managedBy': 'code-to-cloud-security-dojo'
  'dojo.demo': 'drowsy-dragon'
  'dojo.scanHash': scanHash
}

resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = {
  name: registryName
}
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
resource dragon 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    osType: 'Linux'
    restartPolicy: 'Always'
    imageRegistryCredentials: [
      { server: registry.properties.loginServer, identity: identity.id }
    ]
    // No IP address, exposed ports, HTTP probes, credentials or command override.
    containers: [
      {
        name: 'drowsy-dragon'
        properties: {
          image: '${registry.properties.loginServer}/${name}@${imageDigest}'
          resources: { requests: { cpu: 1, memoryInGB: 1 } }
        }
      }
    ]
  }
  dependsOn: [pull]
}
output id string = dragon.id
