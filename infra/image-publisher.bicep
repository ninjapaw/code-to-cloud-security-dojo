@description('Owned training lab identifier.')
param labId string

@description('Region of the existing training resource group.')
param location string = resourceGroup().location

@description('Existing Azure Container Registry used by the image build.')
param registryName string

@description('Immutable GitHub repository subject for the dev-only code-to-cloud-images environment.')
@minLength(1)
param githubEnvironmentSubject string

var acrPushRole = '8311e382-0749-4cb8-b61a-304f252e45ec'
var readerRole = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'

resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = {
  name: registryName
}

resource publisher 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: '${registryName}-publisher'
  location: location
  tags: {
    'dojo.labId': labId
    'dojo.managedBy': 'code-to-cloud-security-dojo'
    'dojo.purpose': 'image-publishing'
  }
}

resource github 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2024-11-30' = {
  parent: publisher
  name: 'github-images'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    audiences: ['api://AzureADTokenExchange']
    subject: githubEnvironmentSubject
  }
}

resource push 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, publisher.id, acrPushRole)
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPushRole)
    principalId: publisher.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// The build checks resource-group ownership tags before any registry write.
resource ownershipReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, publisher.id, readerRole)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', readerRole)
    principalId: publisher.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

output clientId string = publisher.properties.clientId
output principalId string = publisher.properties.principalId
output identityId string = publisher.id
