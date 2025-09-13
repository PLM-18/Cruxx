import { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { useNavigate } from 'react-router-dom'
import { 
    Plus, 
    Search, 
    Filter, 
    Users, 
    Calendar, 
    Shield, 
    Award, 
    TrendingUp, 
    FileText,
    Settings,
    Eye,
    Edit,
    Trash2,
    Clock,
    CheckCircle,
    AlertTriangle,
    Star,
    Lock,
    Activity,
    UserCheck
} from 'lucide-react'
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
                                <option value="all">All Status</option>
                                <option value="Active">Active</option>
                                <option value="Archived">Archived</option>
                                <option value="Closed">Closed</option>
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
