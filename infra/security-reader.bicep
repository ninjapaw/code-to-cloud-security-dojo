targetScope = 'subscription'
param portalPrincipalId string
param labId string
resource securityReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, portalPrincipalId, 'dojo-security-reader')
  properties: {
    principalId: portalPrincipalId
    principalType: 'ServicePrincipal'
    description: 'CodeToCloud:${labId}'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '39bc4728-0917-49c7-9d2c-d95423bc2eb4')
  }
}
output assignmentId string = securityReader.id
