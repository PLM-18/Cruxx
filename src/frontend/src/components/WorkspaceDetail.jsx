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
