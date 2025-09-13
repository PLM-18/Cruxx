import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { 
    ArrowLeft,
    Upload,
    FileText,
    Image,
    Video,
    Music,
    Archive,
    Shield,
    Hash,
    Calendar,
    User,
    Download,
    Eye,
    MessageSquare,
    Plus,
    Search,
    Filter,
    Award,
    Clock,
    CheckCircle,
    AlertTriangle,
    Users,
    Settings,
    Trash2,
    Activity,
    UserPlus,
    UserMinus,
    Crown
} from 'lucide-react'
import toast from 'react-hot-toast'

export default function WorkspaceDetail() {
    const { id } = useParams()
    const navigate = useNavigate()
    const { user } = useAuth()
    
    const [workspace, setWorkspace] = useState(null)
    const [evidence, setEvidence] = useState([])
    const [availableUsers, setAvailableUsers] = useState([])
    const [loading, setLoading] = useState(true)
    const [uploading, setUploading] = useState(false)
    const [showUploadModal, setShowUploadModal] = useState(false)
    const [showAddMemberModal, setShowAddMemberModal] = useState(false)
    const [searchTerm, setSearchTerm] = useState('')
    const [filterType, setFilterType] = useState('all')
    
    const [uploadData, setUploadData] = useState({
        file: null,
        description: '',
        tags: ''
    })

    const [newMember, setNewMember] = useState({
        userId: '',
        role: 'Analyst'
    })

    useEffect(() => {
        fetchWorkspaceDetails()
        fetchEvidence()
    }, [id])

    const fetchWorkspaceDetails = async () => {
        try {
            const response = await fetch(`http://localhost:3000/workspaces/${id}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            })
            
            if (response.ok) {
                const data = await response.json()
                setWorkspace(data)
                
                // Fetch available users if user can manage the workspace
                if (user?.role === 'Admin' || data.user_role === 'Manager') {
                    fetchAvailableUsers()
                }
            } else {
                toast.error('Failed to load workspace details')
                navigate('/workspaces')
            }
        } catch (error) {
            console.error('Error fetching workspace:', error)
            toast.error('Error loading workspace')
            navigate('/workspaces')
        }
    }

    const fetchAvailableUsers = async () => {
        try {
            const response = await fetch(`http://localhost:3000/workspaces/${id}/available-users`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            })
            
            if (response.ok) {
                const data = await response.json()
                setAvailableUsers(data)
            }
        } catch (error) {
            console.error('Error fetching available users:', error)
        }
    }

    const fetchEvidence = async () => {
        try {
            const response = await fetch(`http://localhost:3000/workspaces/${id}/evidence`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            })
            
            if (response.ok) {
                const data = await response.json()
                setEvidence(data)
            } else {
                toast.error('Failed to load evidence')
            }
        } catch (error) {
            console.error('Error fetching evidence:', error)
            toast.error('Error loading evidence')
        } finally {
            setLoading(false)
        }
    }

    const handleFileUpload = async (e) => {
        e.preventDefault()
        
        if (!uploadData.file) {
            toast.error('Please select a file to upload')
            return
        }

        setUploading(true)
        
        const formData = new FormData()
        formData.append('file', uploadData.file)
        formData.append('description', uploadData.description)
        formData.append('tags', uploadData.tags)

        try {
            const response = await fetch(`http://localhost:3000/workspaces/${id}/evidence`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: formData
            })

            if (response.ok) {
                const result = await response.json()
                toast.success('Evidence uploaded successfully!')
                setShowUploadModal(false)
                setUploadData({ file: null, description: '', tags: '' })
                fetchEvidence()
            } else {
                const error = await response.json()
                toast.error(error.error || 'Upload failed')
            }
        } catch (error) {
            console.error('Upload error:', error)
            toast.error('Upload failed')
        } finally {
            setUploading(false)
        }
    }

    const handleAddMember = async (e) => {
        e.preventDefault()
        
        if (!newMember.userId) {
            toast.error('Please select a user to add')
            return
        }

        try {
            const response = await fetch(`http://localhost:3000/workspaces/${id}/members`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    userId: parseInt(newMember.userId),
                    role: newMember.role
                })
            })

            if (response.ok) {
                const result = await response.json()
                toast.success('Team member added successfully!')
                setShowAddMemberModal(false)
                setNewMember({ userId: '', role: 'Analyst' })
                fetchWorkspaceDetails()
                fetchAvailableUsers()
            } else {
                const error = await response.json()
                toast.error(error.error || 'Failed to add member')
            }
        } catch (error) {
            console.error('Add member error:', error)
            toast.error('Failed to add member')
        }
    }

    const handleRemoveMember = async (memberId) => {
        if (!confirm('Are you sure you want to remove this member from the workspace?')) {
            return
        }

        try {
            const response = await fetch(`http://localhost:3000/workspaces/${id}/members/${memberId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            })

            if (response.ok) {
                toast.success('Member removed successfully!')
                fetchWorkspaceDetails()
                fetchAvailableUsers()
            } else {
                const error = await response.json()
                toast.error(error.error || 'Failed to remove member')
            }
        } catch (error) {
            console.error('Remove member error:', error)
            toast.error('Failed to remove member')
        }
    }

    const getFileIcon = (mimeType) => {
        if (mimeType.startsWith('image/')) return <Image className="h-5 w-5 text-blue-500" />
        if (mimeType.startsWith('video/')) return <Video className="h-5 w-5 text-purple-500" />
        if (mimeType.startsWith('audio/')) return <Music className="h-5 w-5 text-green-500" />
        if (mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('7z')) 
            return <Archive className="h-5 w-5 text-orange-500" />
        return <FileText className="h-5 w-5 text-gray-500" />
    }

    const formatFileSize = (bytes) => {
        if (bytes === 0) return '0 Bytes'
        const k = 1024
        const sizes = ['Bytes', 'KB', 'MB', 'GB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
    }

    const getMemberRoleIcon = (role) => {
        switch (role) {
            case 'Manager': return <Crown className="h-4 w-4 text-yellow-500" />
            case 'Admin': return <Shield className="h-4 w-4 text-red-500" />
            default: return <User className="h-4 w-4 text-blue-500" />
        }
    }

    const filteredEvidence = evidence.filter(item => {
        const matchesSearch = item.original_filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            item.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            item.tags?.toLowerCase().includes(searchTerm.toLowerCase())
        
        const matchesFilter = filterType === 'all' || 
                            (filterType === 'images' && item.mime_type.startsWith('image/')) ||
                            (filterType === 'documents' && (item.mime_type.includes('pdf') || item.mime_type.includes('document') || item.mime_type.includes('text'))) ||
                            (filterType === 'media' && (item.mime_type.startsWith('video/') || item.mime_type.startsWith('audio/'))) ||
                            (filterType === 'archives' && (item.mime_type.includes('zip') || item.mime_type.includes('rar')))
        
        return matchesSearch && matchesFilter
    })

    // Check if user can manage team members
    const canManageMembers = user?.role === 'Admin' || workspace?.user_role === 'Manager'

    if (loading) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 flex items-center justify-center">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-white mx-auto mb-4"></div>
                    <p className="text-white text-lg">Loading workspace...</p>
                </div>
            </div>
        )
    }

    if (!workspace) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 flex items-center justify-center">
                <div className="text-center">
                    <AlertTriangle className="h-16 w-16 text-red-400 mx-auto mb-4" />
                    <h2 className="text-2xl font-bold text-white mb-2">Workspace Not Found</h2>
                    <p className="text-slate-300 mb-6">The requested workspace could not be loaded.</p>
                    <button
                        onClick={() => navigate('/workspaces')}
                        className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors"
                    >
                        Back to Workspaces
                    </button>
                </div>
            </div>
        )
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 p-6">
            {/* Header */}
            <div className="max-w-7xl mx-auto mb-8">
                <div className="bg-white/10 backdrop-blur-md rounded-2xl p-6 border border-white/20">
                    <div className="flex items-center gap-4 mb-6">
                        <button
                            onClick={() => navigate('/workspaces')}
                            className="p-2 bg-white/10 rounded-lg hover:bg-white/20 transition-colors"
                        >
                            <ArrowLeft className="h-5 w-5 text-white" />
                        </button>
                        <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                                <Shield className="h-6 w-6 text-blue-400" />
                                <h1 className="text-2xl font-bold text-white">{workspace.name}</h1>
                                {workspace.case_number && (
                                    <span className="px-3 py-1 bg-blue-500/20 text-blue-300 rounded-full text-sm font-semibold border border-blue-400/30">
                                        Case #{workspace.case_number}
                                    </span>
                                )}
                            </div>
                            {workspace.description && (
                                <p className="text-slate-300">{workspace.description}</p>
                            )}
                        </div>
                        
                        {/* Action Buttons */}
                        <div className="flex gap-3">
                            <button
                                onClick={() => setShowUploadModal(true)}
                                className="flex items-center gap-2 bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white px-4 py-2 rounded-lg font-semibold transition-all duration-200 transform hover:scale-105"
                            >
                                <Upload className="h-4 w-4" />
                                Upload Evidence
                            </button>
                            {canManageMembers && (
                                <button
                                    onClick={() => setShowAddMemberModal(true)}
                                    className="flex items-center gap-2 bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 text-white px-4 py-2 rounded-lg font-semibold transition-all duration-200 transform hover:scale-105"
                                >
                                    <UserPlus className="h-4 w-4" />
                                    Add Member
                                </button>
                            )}
                            <button className="p-2 bg-white/10 rounded-lg hover:bg-white/20 transition-colors">
                                <Settings className="h-5 w-5 text-white" />
                            </button>
                        </div>
                    </div>

                    {/* Workspace Stats */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                        <div className="bg-blue-500/20 rounded-xl p-4 border border-blue-400/30">
                            <div className="flex items-center gap-2 text-blue-300 mb-1">
                                <FileText className="h-4 w-4" />
                                <span className="text-sm font-semibold">Evidence Files</span>
                            </div>
                            <p className="text-xl font-bold text-white">{evidence.length}</p>
                        </div>
                        <div className="bg-purple-500/20 rounded-xl p-4 border border-purple-400/30">
                            <div className="flex items-center gap-2 text-purple-300 mb-1">
                                <Users className="h-4 w-4" />
                                <span className="text-sm font-semibold">Team Members</span>
                            </div>
                            <p className="text-xl font-bold text-white">{workspace.members?.length || 0}</p>
                        </div>
                        <div className="bg-green-500/20 rounded-xl p-4 border border-green-400/30">
                            <div className="flex items-center gap-2 text-green-300 mb-1">
                                <CheckCircle className="h-4 w-4" />
                                <span className="text-sm font-semibold">Status</span>
                            </div>
                            <p className="text-lg font-bold text-white">{workspace.status}</p>
                        </div>
                        <div className="bg-orange-500/20 rounded-xl p-4 border border-orange-400/30">
                            <div className="flex items-center gap-2 text-orange-300 mb-1">
                                <Clock className="h-4 w-4" />
                                <span className="text-sm font-semibold">Created</span>
                            </div>
                            <p className="text-sm font-bold text-white">
                                {new Date(workspace.created_at).toLocaleDateString()}
                            </p>
                        </div>
                    </div>

                    {/* Team Members Section */}
                    {workspace.members && workspace.members.length > 0 && (
                        <div className="bg-slate-800/30 rounded-xl p-4 border border-slate-700/50">
                            <h3 className="text-lg font-semibold text-white mb-3">Team Members</h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                                {workspace.members.map((member) => (
                                    <div key={member.id} className="bg-white/10 rounded-lg p-3 border border-white/20">
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                {getMemberRoleIcon(member.role)}
                                                <div>
                                                    <p className="text-white font-semibold text-sm">
                                                        {member.name} {member.surname}
                                                    </p>
                                                    <p className="text-slate-400 text-xs">{member.email}</p>
                                                    <span className="inline-block px-2 py-1 bg-slate-700 text-slate-300 text-xs rounded mt-1">
                                                        {member.role}
                                                    </span>
                                                </div>
                                            </div>
                                            {canManageMembers && member.role !== 'Manager' && (
                                                <button
                                                    onClick={() => handleRemoveMember(member.user_id)}
                                                    className="p-1 text-red-400 hover:text-red-300 hover:bg-red-500/20 rounded transition-colors"
                                                    title="Remove member"
                                                >
                                                    <UserMinus className="h-4 w-4" />
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            </div>
