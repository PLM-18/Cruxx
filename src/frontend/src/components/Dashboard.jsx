import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import {
    Image,
    FileText,
    Shield,
    Users,
    BarChart3,
    Plus,
    Eye,
    Settings,
    CheckCircle,
    XCircle,
    Search,
    Database,
    Lock,
    AlertTriangle
} from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'

export default function Dashboard() {
    const { user } = useAuth()
    const [stats, setStats] = useState({
        images: 0,
        documents: 0,
        confidential: 0,
        totalUsers: 0
    })
    const [recentActivity, setRecentActivity] = useState([])
    const [mfaEnabled, setMfaEnabled] = useState(false)

    useEffect(() => {
        console.log("user", user);

        fetchDashboardData()
        checkMFAStatus()
    }, [])

    const fetchDashboardData = async () => {
        try {
            // Fetch file counts
            const endpoints = ['images', 'documents', 'confidential']
            const fileCounts = {}

            for (const endpoint of endpoints) {
                try {
                    const response = await axios.get(`/${endpoint}?action=list`)
                    fileCounts[endpoint] = response.data.length
                } catch (error) {
                    fileCounts[endpoint] = 0
                }
            }

            // Fetch user count (Admin/Manager only)
            let totalUsers = 0
            if (user.role === 'Admin' || user.role === 'Manager') {
                try {
                    const response = await axios.get('/manage')
                    totalUsers = response.data.length
                } catch (error) {
                    console.log('Could not fetch user count')
                }
            }

            setStats({
                images: fileCounts.images,
                documents: fileCounts.documents,
                confidential: fileCounts.confidential,
                totalUsers
            })

            // Fetch recent activity (Admin/Manager only)
            if (user.role === 'Admin' || user.role === 'Manager') {
                try {
                    const response = await axios.get('/analytics')
                    setRecentActivity(response.data.logs.slice(0, 5))
                } catch (error) {
                    console.log('Could not fetch recent activity')
                }
            }
        } catch (error) {
            console.error('Error fetching dashboard data:', error)
        }
    }

    const checkMFAStatus = async () => {
        const response = await axios.get(`/mfa-status`)
        setMfaEnabled(response.data.mfaEnabled || false)
    }

    const getPermissions = () => {
        const permissions = {
            Admin: {
                images: ['create', 'read', 'write', 'delete'],
                documents: ['create', 'read', 'write', 'delete'],
                confidential: ['create', 'read', 'write', 'delete']
            },
            Manager: {
                images: ['create', 'read', 'write', 'delete'],
                documents: ['create', 'read', 'write', 'delete'],
                confidential: ['create', 'read', 'write']
            },
            Analyst: {
                images: ['create', 'read', 'write'],
                documents: ['create', 'read', 'write'],
                confidential: ['read']
            }
        }

        return permissions[user.role] || {}
    }

    const permissions = getPermissions()

    const formatTimestamp = (timestamp) => {
        return new Date(timestamp).toLocaleString()
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="bg-gradient-to-r from-slate-50 to-blue-50 rounded-2xl p-6 border border-slate-200">
                <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                        <div className="relative">
                            <div className="bg-gradient-to-r from-blue-600 to-indigo-600 rounded-xl p-3 shadow-lg">
                                <Database className="h-8 w-8 text-white" />
                            </div>
                            <div className="absolute -top-1 -right-1 bg-green-500 rounded-full p-1">
                                <Search className="h-3 w-3 text-white" />
                            </div>
                        </div>
                        <div>
                            <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                                ForensicLink Dashboard
                            </h1>
                            <p className="text-slate-600 text-lg">
                                Welcome back, <span className="font-semibold">{user.name}</span> • <span className="text-blue-600 font-medium">{user.role}</span>
                            </p>
                            <p className="text-slate-500 text-sm mt-1">
                                Digital Evidence Collaboration Platform • Secure • Professional
                            </p>
                        </div>
                    </div>
                    <div className="text-right">
                        <div className="text-sm text-slate-500">Role-Based Access</div>
                        <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${user.role === 'Admin' ? 'bg-red-100 text-red-800' :
                                user.role === 'Manager' ? 'bg-blue-100 text-blue-800' :
                                    'bg-green-100 text-green-800'
                            }`}>
                            <Shield className="h-4 w-4 mr-1" />
                            {user.role}
                        </div>
                    </div>
                </div>
            </div>

            {/* Security Status Alert */}
            {!mfaEnabled && (
                <div className="bg-gradient-to-r from-amber-50 to-orange-50 border border-amber-200 rounded-xl p-4 shadow-sm">
                    <div className="flex items-center">
                        <div className="bg-amber-100 rounded-full p-2 mr-4">
                            <AlertTriangle className="h-5 w-5 text-amber-600" />
                        </div>
                        <div className="flex-1">
                            <h3 className="text-sm font-semibold text-amber-800">
                                Enhanced Security Available
                            </h3>
                            <p className="text-sm text-amber-700 mt-1">
                                Strengthen your ForensicLink account with email-based verification for enhanced evidence security.
                            </p>
                        </div>
                        <Link
                            to="/mfa-setup"
                            className="bg-gradient-to-r from-amber-600 to-orange-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:from-amber-700 hover:to-orange-700 transition-all duration-200 shadow-md"
                        >
                            <Lock className="h-4 w-4 inline mr-1" />
                            Enable Email Verification
                        </Link>
                    </div>
                </div>
            )}

            {mfaEnabled && (
                <div className="bg-gradient-to-r from-emerald-50 to-green-50 border border-emerald-200 rounded-xl p-4 shadow-sm">
                    <div className="flex items-center">
                        <div className="bg-emerald-100 rounded-full p-2 mr-4">
                            <CheckCircle className="h-5 w-5 text-emerald-600" />
                        </div>
                        <div>
                            <h3 className="text-sm font-semibold text-emerald-800">
                                Security Enhanced
                            </h3>
                            <p className="text-sm text-emerald-700">
                                Your ForensicLink account is protected with email-based verification.
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {/* Images Card */}
                <div className="card p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm text-gray-600">Images</p>
                            <p className="text-3xl font-bold text-gray-900">{stats.images}</p>
                        </div>
                        <div className="bg-blue-100 rounded-full p-3">
                            <Image className="h-6 w-6 text-blue-600" />
                        </div>
                    </div>
                    <div className="mt-4 flex justify-between items-center">
                        <div className="text-xs text-gray-500">
                            Permissions: {permissions.images?.join(', ') || 'None'}
                        </div>
                        {permissions.images?.length > 0 && (
                            <Link
                                to="/files/images"
                                className="text-blue-600 hover:text-blue-700 text-sm font-medium"
                            >
                                View <Eye className="inline h-4 w-4 ml-1" />
                            </Link>
                        )}
                    </div>
                </div>

                {/* Documents Card */}
                <div className="card p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm text-gray-600">Documents</p>
                            <p className="text-3xl font-bold text-gray-900">{stats.documents}</p>
                        </div>
                        <div className="bg-green-100 rounded-full p-3">
                            <FileText className="h-6 w-6 text-green-600" />
                        </div>
                    </div>
                    <div className="mt-4 flex justify-between items-center">
                        <div className="text-xs text-gray-500">
                            Permissions: {permissions.documents?.join(', ') || 'None'}
                        </div>
                        {permissions.documents?.length > 0 && (
                            <Link
                                to="/files/documents"
                                className="text-green-600 hover:text-green-700 text-sm font-medium"
                            >
                                View <Eye className="inline h-4 w-4 ml-1" />
                            </Link>
                        )}
                    </div>
                </div>

                {/* Confidential Card */}
                <div className="card p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm text-gray-600">Confidential</p>
                            <p className="text-3xl font-bold text-gray-900">{stats.confidential}</p>
                        </div>
                        <div className="bg-red-100 rounded-full p-3">
                            <Shield className="h-6 w-6 text-red-600" />
                        </div>
                    </div>
                    <div className="mt-4 flex justify-between items-center">
                        <div className="text-xs text-gray-500">
                            Permissions: {permissions.confidential?.join(', ') || 'None'}
                        </div>
                        {permissions.confidential?.length > 0 && (
                            <Link
                                to="/files/confidential"
                                className="text-red-600 hover:text-red-700 text-sm font-medium"
                            >
                                View <Eye className="inline h-4 w-4 ml-1" />
                            </Link>
                        )}
                    </div>
                </div>

                {/* Users Card (Admin/Manager only) */}
                {(user.role === 'Admin' || user.role === 'Manager') && (
                    <div className="card p-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-sm text-gray-600">Total Users</p>
                                <p className="text-3xl font-bold text-gray-900">{stats.totalUsers}</p>
                            </div>
                            <div className="bg-purple-100 rounded-full p-3">
                                <Users className="h-6 w-6 text-purple-600" />
                            </div>
                        </div>
                        <div className="mt-4 flex justify-between items-center">
                            <div className="text-xs text-gray-500">
                                System Users
                            </div>
                            <Link
                                to="/manage"
                                className="text-purple-600 hover:text-purple-700 text-sm font-medium"
                            >
                                Manage <Settings className="inline h-4 w-4 ml-1" />
                            </Link>
                        </div>
                    </div>
                )}
            </div>

            {/* Quick Actions */}
            <div className="card p-6">
                <h2 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {permissions.images?.includes('create') && (
                        <Link
                            to="/files/images"
                            className="flex items-center p-4 bg-blue-50 rounded-lg hover:bg-blue-100 transition-colors"
                        >
                            <Plus className="h-5 w-5 text-blue-600 mr-3" />
                            <span className="text-blue-700 font-medium w-fit">Upload Image</span>
                        </Link>
                    )}

                    {permissions.documents?.includes('create') && (
                        <Link
                            to="/files/documents"
                            className="flex items-center p-4 bg-green-50 rounded-lg hover:bg-green-100 transition-colors"
                        >
                            <Plus className="h-5 w-5 text-green-600 mr-3" />
                            <span className="text-green-700 font-medium">Upload Document</span>
                        </Link>
                    )}

                    {permissions.confidential?.includes('create') && (
                        <Link
                            to="/files/confidential"
                            className="flex items-center p-4 bg-red-50 rounded-lg hover:bg-red-100 transition-colors"
                        >
                            <Plus className="h-5 w-5 text-red-600 mr-3" />
                            <span className="text-red-700 font-medium">Create Confidential</span>
                        </Link>
                    )}

                    {(user.role === 'Admin' || user.role === 'Manager') && (
                        <Link
                            to="/analytics"
                            className="flex items-center p-4 bg-purple-50 rounded-lg hover:bg-purple-100 transition-colors"
                        >
                            <BarChart3 className="h-5 w-5 text-purple-600 mr-3" />
                            <span className="text-purple-700 font-medium">View Analytics</span>
                        </Link>
                    )}
                </div>
            </div>

            {/* Recent Activity (Admin/Manager only) */}
            {(user.role === 'Admin' || user.role === 'Manager') && recentActivity.length > 0 && (
                <div className="card p-6">
                    <h2 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h2>
                    <div className="space-y-3">
                        {recentActivity.map((activity, index) => (
                            <div key={index} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-b-0">
                                <div className="flex items-center space-x-3">
                                    <div className={`w-2 h-2 rounded-full ${activity.success ? 'bg-green-400' : 'bg-red-400'}`}></div>
                                    <div>
                                        <p className="text-sm text-gray-900">
                                            {activity.name || 'Unknown'} {activity.surname || 'User'} - {activity.endpoint} ({activity.action})
                                        </p>
                                        <p className="text-xs text-gray-500">
                                            {activity.ip_address} • {formatTimestamp(activity.timestamp)}
                                        </p>
                                    </div>
                                </div>
                                <div className={`px-2 py-1 rounded-full text-xs font-medium ${activity.success
                                    ? 'bg-green-100 text-green-800'
                                    : 'bg-red-100 text-red-800'
                                    }`}>
                                    {activity.success ? 'Success' : 'Failed'}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    )
}