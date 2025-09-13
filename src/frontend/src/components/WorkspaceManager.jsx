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
