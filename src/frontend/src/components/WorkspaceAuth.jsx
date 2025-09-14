export const getWorkspaceToken = (workspaceId) => {
    return localStorage.getItem(`workspace_token_${workspaceId}`)
}

export const clearWorkspaceToken = (workspaceId) => {
    localStorage.removeItem(`workspace_token_${workspaceId}`)
}

export const createAuthenticatedFetch = (workspaceId) => {
    const token = localStorage.getItem('token')
    const workspaceToken = getWorkspaceToken(workspaceId)
    
    return {
        headers: {
            'Authorization': `Bearer ${token}`,
            'X-Workspace-Token': workspaceToken,
            'Content-Type': 'application/json'
        }
    }
}