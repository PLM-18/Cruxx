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
