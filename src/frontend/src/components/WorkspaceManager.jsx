import { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { useNavigate } from 'react-router-dom'
import { 
    Plus, Search, Filter, Users, Calendar, Shield, Award, TrendingUp, FileText, Settings, Eye, Edit, Trash2, Clock, CheckCircle, AlertTriangle, Star, Lock, Activity, UserCheck
} from 'lucide-react'
import WorkspaceAuthModal from './WorkspaceAuthModal'
import toast from 'react-hot-toast'

export default function WorkspaceManager() {
    const { user } = useAuth()
    const navigate = useNavigate()
    const [workspaces, setWorkspaces] = useState([])
    const [managers, setManagers] = useState([])
    const [loading, setLoading] = useState(true)
    const [showCreateModal, setShowCreateModal] = useState(false)
    const [searchTerm, setSearchTerm] = useState('')
    const [filterStatus, setFilterStatus] = useState('all')
    const [showAuthModal, setShowAuthModal] = useState(false)
    const [selectedWorkspaceForAuth, setSelectedWorkspaceForAuth] = useState(null)
    const [authLoading, setAuthLoading] = useState(false)

    const [newWorkspace, setNewWorkspace] = useState({
        name: '',
        description: '',
        case_number: '',
        assigned_manager: ''
    })

    // Only Admins can create workspaces
    const canCreateWorkspace = user?.role === 'Admin'

    useEffect(() => {
        fetchWorkspaces()
        if (canCreateWorkspace) {
            fetchManagers()
        }
    }, [])

    const handleWorkspaceClick = (workspace) => {
        setSelectedWorkspaceForAuth(workspace)
        setShowAuthModal(true)
    }

    // Add authentication function
    const authenticateWorkspace = async (password) => {
        if (!selectedWorkspaceForAuth) return
        
        setAuthLoading(true)
        
        try {
            const email = user.email;
            const response = await fetch(`http://localhost:3000/verify-credentials`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({ password, email })
            })
            
            const data = await response.json()
            
            if (response.ok && data.valid) {
                // Authentication successful - proceed to workspace
                setShowAuthModal(false)
                setSelectedWorkspaceForAuth(null)
                navigate(`/workspaces/${selectedWorkspaceForAuth.id}`)
                toast.success('Workspace access granted')
            } else {
                toast.error('Invalid credentials')
            }
        } catch (error) {
            console.error('Workspace authentication error:', error)
            toast.error('Authentication failed')
        } finally {
            setAuthLoading(false)
        }
    }

    const fetchWorkspaces = async () => {
        try {
            const response = await fetch('http://localhost:3000/workspaces', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            })
            
            if (response.ok) {
                const data = await response.json()
                setWorkspaces(data)
            } else {
                toast.error('Failed to fetch workspaces')
            }
        } catch (error) {
            console.error('Error fetching workspaces:', error)
            toast.error('Error loading workspaces')
        } finally {
            setLoading(false)
        }
    }

    const fetchManagers = async () => {
        try {
            const response = await fetch('http://localhost:3000/managers', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            })
            
            if (response.ok) {
                const data = await response.json()
                setManagers(data)
            }
        } catch (error) {
            console.error('Error fetching managers:', error)
        }
    }

    const createWorkspace = async (e) => {
        e.preventDefault()
        
        if (!newWorkspace.name.trim()) {
            toast.error('Workspace name is required')
            return
        }

        if (!newWorkspace.assigned_manager) {
            toast.error('Manager assignment is required')
            return
        }

        try {
            const response = await fetch('http://localhost:3000/workspaces', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify(newWorkspace)
            })

            if (response.ok) {
                const data = await response.json()
                toast.success('Workspace created and manager assigned successfully!')
                setShowCreateModal(false)
                setNewWorkspace({ name: '', description: '', case_number: '', assigned_manager: '' })
                fetchWorkspaces()
            } else {
                const error = await response.json()
                toast.error(error.error || 'Failed to create workspace')
            }
        } catch (error) {
            console.error('Error creating workspace:', error)
            toast.error('Error creating workspace')
        }
    }

    const getStatusColor = (status) => {
        switch (status) {
            case 'Active': return 'bg-green-100 text-green-800 border-green-200'
            case 'Archived': return 'bg-gray-100 text-gray-800 border-gray-200'
            case 'Closed': return 'bg-red-100 text-red-800 border-red-200'
            default: return 'bg-blue-100 text-blue-800 border-blue-200'
        }
    }

    const getRoleIcon = (role) => {
        switch (role) {
            case 'Admin': return <Shield className="h-4 w-4 text-red-500" />
            case 'Manager': return <Users className="h-4 w-4 text-blue-500" />
            default: return <Eye className="h-4 w-4 text-green-500" />
        }
    }

    const filteredWorkspaces = workspaces.filter(workspace => {
        const matchesSearch = workspace.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            workspace.case_number?.toLowerCase().includes(searchTerm.toLowerCase())
        const matchesFilter = filterStatus === 'all' || workspace.status === filterStatus
        return matchesSearch && matchesFilter
    })

    if (loading) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 flex items-center justify-center">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-white mx-auto mb-4"></div>
                    <p className="text-white text-lg">Loading workspaces...</p>
                </div>
            </div>
        )
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 p-6">
            {/* Header with Gamification */}
            <div className="max-w-7xl mx-auto mb-8">
                <div className="bg-white/10 backdrop-blur-md rounded-2xl p-6 border border-white/20">
                    <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
                        <div>
                            <h1 className="text-3xl font-bold text-white mb-2">Investigation Workspaces</h1>
                            <p className="text-blue-100">
                                {user?.role === 'Admin' 
                                    ? "Create and oversee all investigation workspaces"
                                    : user?.role === 'Manager'
                                    ? "Manage your assigned investigation teams"
                                    : "Collaborate on digital forensics investigations"
                                }
                            </p>
                        </div>
                        
                        {/* Gamification Stats */}
                        <div className="flex gap-4">
                            <div className="bg-green-500/20 rounded-xl p-4 border border-green-400/30">
                                <div className="flex items-center gap-2 text-green-300">
                                    <Award className="h-5 w-5" />
                                    <span className="font-semibold">Security Score</span>
                                </div>
                                <p className="text-2xl font-bold text-white mt-1">98%</p>
                            </div>
                            <div className="bg-blue-500/20 rounded-xl p-4 border border-blue-400/30">
                                <div className="flex items-center gap-2 text-blue-300">
                                    <TrendingUp className="h-5 w-5" />
                                    <span className="font-semibold">Active Cases</span>
                                </div>
                                <p className="text-2xl font-bold text-white mt-1">{workspaces.length}</p>
                            </div>
                            <div className="bg-purple-500/20 rounded-xl p-4 border border-purple-400/30">
                                <div className="flex items-center gap-2 text-purple-300">
                                    <Activity className="h-5 w-5" />
                                    <span className="font-semibold">Evidence Files</span>
                                </div>
                                <p className="text-2xl font-bold text-white mt-1">
                                    {workspaces.reduce((sum, w) => sum + (w.evidence_count || 0), 0)}
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Controls */}
            <div className="max-w-7xl mx-auto mb-6">
                <div className="flex flex-col lg:flex-row gap-4 lg:items-center lg:justify-between">
                    <div className="flex gap-4">
                        {/* Search */}
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-slate-400" />
                            <input
                                type="text"
                                placeholder="Search workspaces..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="pl-10 pr-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-slate-300 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                        </div>

                        {/* Filter */}
                        <div className="relative">
                            <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-slate-400" />
                            <select
                                value={filterStatus}
                                onChange={(e) => setFilterStatus(e.target.value)}
                                className="pl-10 pr-8 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent appearance-none"
                            >
                                <option style={{ color: 'black' }} value="all">All Status</option>
                                <option style={{ color: 'black' }} value="Active">Active</option>
                                <option style={{ color: 'black' }} value="Archived">Archived</option>
                                <option style={{ color: 'black' }} value="Closed">Closed</option>
                            </select>
                        </div>
                    </div>

                    {/* Create Workspace Button - Admin only */}
                    {canCreateWorkspace && (
                        <button
                            onClick={() => setShowCreateModal(true)}
                            className="flex items-center gap-2 bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white px-6 py-2 rounded-lg font-semibold transition-all duration-200 transform hover:scale-105 shadow-lg"
                        >
                            <Plus className="h-5 w-5" />
                            New Investigation
                        </button>
                    )}
                </div>
            </div>

            {/* Workspaces Grid */}
            <div className="max-w-7xl mx-auto">
                {filteredWorkspaces.length === 0 ? (
                    <div className="text-center py-12">
                        <div className="bg-white/5 rounded-2xl p-8 border border-white/10">
                            <FileText className="h-16 w-16 text-slate-400 mx-auto mb-4" />
                            <h3 className="text-xl font-semibold text-white mb-2">No workspaces found</h3>
                            <p className="text-slate-300 mb-6">
                                {canCreateWorkspace 
                                    ? "Create your first investigation workspace to get started"
                                    : user?.role === 'Manager'
                                    ? "No workspaces assigned to you yet. Contact an admin to be assigned investigations."
                                    : "No workspaces available. Contact a manager to be added to investigations."
                                }
                            </p>
                            {canCreateWorkspace && (
                                <button
                                    onClick={() => setShowCreateModal(true)}
                                    className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
                                >
                                    Create Workspace
                                </button>
                            )}
                        </div>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {filteredWorkspaces.map((workspace) => (
                            <div
                                key={workspace.id}
                                className="bg-white/10 backdrop-blur-md rounded-2xl p-6 border border-white/20 hover:bg-white/15 transition-all duration-200 transform hover:scale-105 cursor-pointer"
                                onClick={() => handleWorkspaceClick(workspace)}
                            >
                                {/* Header */}
                                <div className="flex items-start justify-between mb-4">
                                    <div className="flex items-center gap-2">
                                        <Lock className="h-5 w-5 text-blue-400" />
                                        <span className={`px-2 py-1 rounded-full text-xs font-semibold border ${getStatusColor(workspace.status)}`}>
                                            {workspace.status}
                                        </span>
                                    </div>
                                    <div className="flex items-center gap-1">
                                        {getRoleIcon(workspace.user_role)}
                                        <span className="text-xs text-slate-300">{workspace.user_role}</span>
                                    </div>
                                </div>

                                {/* Content */}
                                <div className="mb-4">
                                    <h3 className="text-lg font-semibold text-white mb-2 line-clamp-1">
                                        {workspace.name}
                                    </h3>
                                    {workspace.case_number && (
                                        <p className="text-sm text-blue-300 mb-2">Case #{workspace.case_number}</p>
                                    )}
                                    {workspace.description && (
                                        <p className="text-sm text-slate-300 line-clamp-2">{workspace.description}</p>
                                    )}
                                </div>

                                {/* Manager Info */}
                                {workspace.manager_name && (
                                    <div className="mb-3 p-2 bg-blue-500/20 rounded-lg border border-blue-400/30">
                                        <div className="flex items-center gap-2 text-blue-300">
                                            <UserCheck className="h-3 w-3" />
                                            <span className="text-xs font-semibold">Manager:</span>
                                        </div>
                                        <p className="text-xs text-white">
                                            {workspace.manager_name} {workspace.manager_surname}
                                        </p>
                                    </div>
                                )}

                                {/* Footer */}
                                <div className="flex items-center justify-between text-xs text-slate-400">
                                    <div className="flex items-center gap-4">
                                        <div className="flex items-center gap-1">
                                            <FileText className="h-4 w-4" />
                                            <span>{workspace.evidence_count || 0} files</span>
                                        </div>
                                        <div className="flex items-center gap-1">
                                            <Calendar className="h-4 w-4" />
                                            <span>{new Date(workspace.created_at).toLocaleDateString()}</span>
                                        </div>
                                    </div>
                                </div>

                                {/* Creator info */}
                                <div className="mt-3 pt-3 border-t border-white/10">
                                    <p className="text-xs text-slate-400">
                                        Created by {workspace.creator_name} {workspace.creator_surname}
                                    </p>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Create Workspace Modal - Admin Only */}
            {showCreateModal && (
                <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
                    <div className="bg-white rounded-2xl p-6 w-full max-w-md">
                        <h2 className="text-2xl font-bold text-slate-800 mb-6">Create New Investigation</h2>
                        
                        <form onSubmit={createWorkspace} className="space-y-4">
                            <div>
                                <label className="block text-sm font-semibold text-slate-700 mb-2">
                                    Investigation Name *
                                </label>
                                <input
                                    type="text"
                                    value={newWorkspace.name}
                                    onChange={(e) => setNewWorkspace({...newWorkspace, name: e.target.value})}
                                    className="w-full px-4 py-3 border border-slate-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    placeholder="e.g., Ransomware Attack Investigation"
                                    required
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-semibold text-slate-700 mb-2">
                                    Assign Manager *
                                </label>
                                <select
                                    value={newWorkspace.assigned_manager}
                                    onChange={(e) => setNewWorkspace({...newWorkspace, assigned_manager: e.target.value})}
                                    className="w-full px-4 py-3 border border-slate-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    required
                                >
                                    <option value="">Select a manager...</option>
                                    {managers.map(manager => (
                                        <option key={manager.id} value={manager.id}>
                                            {manager.name} {manager.surname} ({manager.email})
                                        </option>
                                    ))}
                                </select>
                                <p className="text-xs text-slate-500 mt-1">
                                    The selected manager will be able to add team members to this workspace
                                </p>
                            </div>

                            <div>
                                <label className="block text-sm font-semibold text-slate-700 mb-2">
                                    Case Number
                                </label>
                                <input
                                    type="text"
                                    value={newWorkspace.case_number}
                                    onChange={(e) => setNewWorkspace({...newWorkspace, case_number: e.target.value})}
                                    className="w-full px-4 py-3 border border-slate-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    placeholder="e.g., CASE-2024-001"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-semibold text-slate-700 mb-2">
                                    Description
                                </label>
                                <textarea
                                    value={newWorkspace.description}
                                    onChange={(e) => setNewWorkspace({...newWorkspace, description: e.target.value})}
                                    className="w-full px-4 py-3 border border-slate-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    rows="3"
                                    placeholder="Brief description of the investigation..."
                                />
                            </div>

                            <div className="flex gap-3 pt-4">
                                <button
                                    type="button"
                                    onClick={() => setShowCreateModal(false)}
                                    className="flex-1 px-4 py-3 border border-slate-300 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="flex-1 bg-gradient-to-r from-blue-600 to-indigo-600 text-white px-4 py-3 rounded-lg hover:from-blue-700 hover:to-indigo-700 transition-all duration-200 font-semibold"
                                >
                                    Create & Assign
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
            {showAuthModal && selectedWorkspaceForAuth && (
                <WorkspaceAuthModal
                    workspace={selectedWorkspaceForAuth}
                    onAuthenticate={authenticateWorkspace}
                    onClose={() => {
                        setShowAuthModal(false)
                        setSelectedWorkspaceForAuth(null)
                    }}
                    loading={authLoading}
                />
            )}
        </div>
    )
}