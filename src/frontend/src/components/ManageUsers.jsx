import { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import {
    Users,
    Check,
    X,
    Shield,
    UserCheck,
    UserX,
    Crown,
    User,
    Eye
} from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'

export default function ManageUsers() {
    const { user } = useAuth()
    const [users, setUsers] = useState([])
    const [loading, setLoading] = useState(true)
    const [actionLoading, setActionLoading] = useState({})

    useEffect(() => {
        fetchUsers()
    }, [])

    const fetchUsers = async () => {
        try {
            const response = await axios.get('/manage')
            setUsers(response.data)
        } catch (error) {
            toast.error('Failed to fetch users')
        } finally {
            setLoading(false)
        }
    }

    const handleApproveUser = async (userId) => {
        setActionLoading({ ...actionLoading, [userId]: 'approving' })

        try {
            await axios.post('/manage/approve', { userId })
            toast.success('User approved successfully')
            fetchUsers()
        } catch (error) {
            toast.error('Failed to approve user')
        } finally {
            setActionLoading({ ...actionLoading, [userId]: null })
        }
    }

    const handleRevokeUser = async (userId) => {
        if (userId === user.id) {
            toast.error('Cannot revoke your own access')
            return
        }

        setActionLoading({ ...actionLoading, [userId]: 'revoking' })

        try {
            await axios.post('/manage/revoke', { userId })
            toast.success('User access revoked')
            fetchUsers()
        } catch (error) {
            toast.error('Failed to revoke user access')
        } finally {
            setActionLoading({ ...actionLoading, [userId]: null })
        }
    }

    const handleRoleChange = async (userId, newRole) => {
        if (userId === user.id && newRole !== user.role) {
            toast.error('Cannot change your own role')
            return
        }

        setActionLoading({ ...actionLoading, [userId]: 'updating' })

        try {
            await axios.post('/manage/role', { userId, role: newRole })
            toast.success(`Role updated to ${newRole}`)
            fetchUsers()
        } catch (error) {
            toast.error('Failed to update role')
        } finally {
            setActionLoading({ ...actionLoading, [userId]: null })
        }
    }

    const getRoleIcon = (role) => {
        switch (role) {
            case 'Admin':
                return <Crown className="h-4 w-4 text-purple-600" />
            case 'Manager':
                return <Shield className="h-4 w-4 text-blue-600" />
            case 'User':
                return <User className="h-4 w-4 text-green-600" />
            case 'Guest':
                return <Eye className="h-4 w-4 text-gray-600" />
            default:
                return <User className="h-4 w-4 text-gray-600" />
        }
    }

    const getRoleBadgeColor = (role) => {
        switch (role) {
            case 'Admin':
                return 'bg-purple-100 text-purple-800'
            case 'Manager':
                return 'bg-blue-100 text-blue-800'
            case 'User':
                return 'bg-green-100 text-green-800'
            case 'Guest':
                return 'bg-gray-100 text-gray-800'
            default:
                return 'bg-gray-100 text-gray-800'
        }
    }

    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        })
    }

    if (loading) {
        return (
            <div className="flex justify-center items-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        )
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">User Management</h1>
                    <p className="text-gray-600">
                        Manage user accounts, roles, and permissions
                    </p>
                </div>
                <div className="flex items-center space-x-2 text-sm text-gray-600">
                    <Users className="h-4 w-4" />
                    <span>{users.length} total users</span>
                </div>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {['Admin', 'Manager', 'User', 'Guest'].map(role => (
                    <div key={role} className="card p-4">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                                {getRoleIcon(role)}
                                <span className="text-sm font-medium text-gray-700">{role}s</span>
                            </div>
                            <span className="text-2xl font-bold text-gray-900">
                                {users.filter(u => u.role === role).length}
                            </span>
                        </div>
                    </div>
                ))}
            </div>

            {/* Users Table */}
            <div className="card overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-200">
                    <h2 className="text-lg font-semibold text-gray-900">All Users</h2>
                </div>

                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    User
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Role
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Status
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Created
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Actions
                                </th>
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                            {users.map((userData) => (
                                <tr key={userData.id} className="hover:bg-gray-50">
                                    {/* User Info */}
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        <div className="flex items-center">
                                            <div className="h-10 w-10 bg-blue-600 rounded-full flex items-center justify-center">
                                                <span className="text-white text-sm font-medium">
                                                    {userData.name[0]}{userData.surname[0]}
                                                </span>
                                            </div>
                                            <div className="ml-4">
                                                <div className="text-sm font-medium text-gray-900">
                                                    {userData.name} {userData.surname}
                                                </div>
                                                <div className="text-sm text-gray-500">
                                                    {userData.email}
                                                </div>
                                            </div>
                                        </div>
                                    </td>

                                    {/* Role */}
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        {user.role === 'Admin' ? (
                                            <select
                                                value={userData.role}
                                                onChange={(e) => handleRoleChange(userData.id, e.target.value)}
                                                disabled={actionLoading[userData.id] === 'updating'}
                                                className="text-sm border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                                            >
                                                <option value="Admin">Admin</option>
                                                <option value="Manager">Manager</option>
                                                <option value="User">User</option>
                                                <option value="Guest">Guest</option>
                                            </select>
                                        ) : (
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRoleBadgeColor(userData.role)}`}>
                                                {getRoleIcon(userData.role)}
                                                <span className="ml-1">{userData.role}</span>
                                            </span>
                                        )}
                                    </td>

                                    {/* Status */}
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        {userData.approved ? (
                                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                                <UserCheck className="h-3 w-3 mr-1" />
                                                Approved
                                            </span>
                                        ) : (
                                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                                <UserX className="h-3 w-3 mr-1" />
                                                Pending
                                            </span>
                                        )}
                                    </td>

                                    {/* Created */}
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        {formatDate(userData.created_at)}
                                    </td>

                                    {/* Actions */}
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                        <div className="flex items-center space-x-2">
                                            {!userData.approved ? (
                                                <button
                                                    onClick={() => handleApproveUser(userData.id)}
                                                    disabled={actionLoading[userData.id] === 'approving'}
                                                    className="text-green-600 hover:text-green-900 disabled:opacity-50"
                                                    title="Approve User"
                                                >
                                                    {actionLoading[userData.id] === 'approving' ? (
                                                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-green-600"></div>
                                                    ) : (
                                                        <Check className="h-4 w-4" />
                                                    )}
                                                </button>
                                            ) : userData.id !== user.id && user.role === 'Admin' && (
                                                <button
                                                    onClick={() => handleRevokeUser(userData.id)}
                                                    disabled={actionLoading[userData.id] === 'revoking'}
                                                    className="text-red-600 hover:text-red-900 disabled:opacity-50"
                                                    title="Revoke Access"
                                                >
                                                    {actionLoading[userData.id] === 'revoking' ? (
                                                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-600"></div>
                                                    ) : (
                                                        <X className="h-4 w-4" />
                                                    )}
                                                </button>
                                            )}

                                            {actionLoading[userData.id] === 'updating' && (
                                                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {users.length === 0 && (
                    <div className="text-center py-12">
                        <Users className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                        <p className="text-gray-500">No users found</p>
                    </div>
                )}
            </div>

            {/* Legend */}
            <div className="card p-4">
                <h3 className="text-sm font-medium text-gray-900 mb-3">Role Permissions</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                        <div className="flex items-center mb-2">
                            <Crown className="h-4 w-4 text-purple-600 mr-2" />
                            <span className="font-medium">Admin:</span>
                            <span className="ml-1 text-gray-600">Full system access</span>
                        </div>
                        <div className="flex items-center mb-2">
                            <Shield className="h-4 w-4 text-blue-600 mr-2" />
                            <span className="font-medium">Manager:</span>
                            <span className="ml-1 text-gray-600">User management + file access</span>
                        </div>
                    </div>
                    <div>
                        <div className="flex items-center mb-2">
                            <User className="h-4 w-4 text-green-600 mr-2" />
                            <span className="font-medium">User:</span>
                            <span className="ml-1 text-gray-600">Read/write files</span>
                        </div>
                        <div className="flex items-center mb-2">
                            <Eye className="h-4 w-4 text-gray-600 mr-2" />
                            <span className="font-medium">Guest:</span>
                            <span className="ml-1 text-gray-600">Read-only access</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}