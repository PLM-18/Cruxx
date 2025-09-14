import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import {
    Upload,
    Download,
    Edit,
    Trash2,
    File,
    Image as ImageIcon,
    FileText,
    Shield,
    Plus,
    X,
    Save,
    Eye,
    EyeOff
} from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'

export default function FileManager() {
    const { type } = useParams()
    const { user } = useAuth()
    const [files, setFiles] = useState([])
    const [loading, setLoading] = useState(true)
    const [uploading, setUploading] = useState(false)
    const [showCreateModal, setShowCreateModal] = useState(false)
    const [showEditModal, setShowEditModal] = useState(false)
    const [editingFile, setEditingFile] = useState(null)
    const [newFileName, setNewFileName] = useState('')
    const [newFileContent, setNewFileContent] = useState('')
    const [editContent, setEditContent] = useState('')

    useEffect(() => {
        fetchFiles()
    }, [type])

    const fetchFiles = async () => {
        setLoading(true)
        try {
            const response = await axios.get(`/${type}?action=list`)
            setFiles(response.data)
        } catch (error) {
            toast.error(`Failed to fetch ${type}`)
        } finally {
            setLoading(false)
        }
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
            User: {
                images: ['read', 'write'],
                documents: ['read', 'write'],
                confidential: ['read']
            },
            Guest: {
                images: ['read'],
                documents: [],
                confidential: []
            }
        }

        return permissions[user.role]?.[type] || []
    }

    const permissions = getPermissions()

    const getFileIcon = () => {
        switch (type) {
            case 'images':
                return <ImageIcon className="h-6 w-6 text-blue-600" />
            case 'documents':
                return <FileText className="h-6 w-6 text-green-600" />
            case 'confidential':
                return <Shield className="h-6 w-6 text-red-600" />
            default:
                return <File className="h-6 w-6 text-gray-600" />
        }
    }

    const getTypeColor = () => {
        switch (type) {
            case 'images':
                return 'blue'
            case 'documents':
                return 'green'
            case 'confidential':
                return 'red'
            default:
                return 'gray'
        }
    }

    const handleFileUpload = async (event) => {
        const file = event.target.files[0]
        if (!file) return

        setUploading(true)
        const formData = new FormData()
        formData.append('file', file)
        formData.append('action', 'create')

        try {
            await axios.post(`/${type}?action=create`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            })
            toast.success('File uploaded successfully')
            fetchFiles()
            event.target.value = '' // Clear the input
        } catch (error) {
            toast.error('Failed to upload file')
        } finally {
            setUploading(false)
        }
    }

    const handleCreateConfidentialFile = async () => {
        if (!newFileName.trim()) {
            toast.error('Please enter a filename')
            return
        }

        try {
            await axios.post(`/confidential`, {
                action: 'create',
                filename: newFileName,
                content: newFileContent
            })
            toast.success('Confidential file created successfully')
            setShowCreateModal(false)
            setNewFileName('')
            setNewFileContent('')
            fetchFiles()
        } catch (error) {
            toast.error('Failed to create file')
        }
    }

    const handleReadFile = async (fileId, fileName) => {
        try {
            if (type === 'confidential') {
                const response = await axios.post(`/${type}`, {
                    action: 'read',
                    fileId
                })
                setEditingFile({ id: fileId, name: fileName })
                setEditContent(response.data.content)
                setShowEditModal(true)
            } else {
                // For images and documents, download the file
                const response = await axios.post(`/${type}`, {
                    action: 'read',
                    fileId
                }, {
                    responseType: 'blob'
                })

                const url = window.URL.createObjectURL(new Blob([response.data]))
                const link = document.createElement('a')
                link.href = url
                link.setAttribute('download', fileName)
                document.body.appendChild(link)
                link.click()
                link.remove()
                window.URL.revokeObjectURL(url)
            }
        } catch (error) {
            toast.error('Failed to read file')
        }
    }

    const handleUpdateFile = async () => {
        try {
            await axios.post(`/${type}`, {
                action: 'write',
                fileId: editingFile.id,
                content: editContent
            })
            toast.success('File updated successfully')
            setShowEditModal(false)
            setEditingFile(null)
            setEditContent('')
            fetchFiles()
        } catch (error) {
            toast.error('Failed to update file')
        }
    }

    const handleDeleteFile = async (fileId, fileName) => {
        if (!window.confirm(`Are you sure you want to delete "${fileName}"?`)) {
            return
        }

        try {
            await axios.post(`/${type}`, {
                action: 'delete',
                fileId
            })
            toast.success('File deleted successfully')
            fetchFiles()
        } catch (error) {
            toast.error('Failed to delete file')
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

    const canPerform = (action) => permissions.includes(action)

    if (loading) {
        return (
            <div className="flex justify-center items-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        )
    }

    const color = getTypeColor()

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                    {getFileIcon()}
                    <div>
                        <h1 className="text-2xl font-bold text-gray-900 capitalize">
                            {type} Files
                        </h1>
                        <p className="text-gray-600">
                            Manage your {type} files with role-based permissions
                        </p>
                    </div>
                </div>

                {/* Upload/Create Actions */}
                <div className="flex items-center space-x-3">
                    {canPerform('create') && type !== 'confidential' && (
                        <div className="relative">
                            <input
                                type="file"
                                id="file-upload"
                                className="hidden"
                                onChange={handleFileUpload}
                                disabled={uploading}
                                accept={type === 'images' ? 'image/*' : '*'}
                            />
                            <label
                                htmlFor="file-upload"
                                className={`btn-primary ${uploading ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
                            >
                                {uploading ? (
                                    <div className="flex items-center">
                                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                                        Uploading...
                                    </div>
                                ) : (
                                    <div className="flex items-center">
                                        <Upload className="h-4 w-4 mr-2" />
                                        Upload {type.slice(0, -1)}
                                    </div>
                                )}
                            </label>
                        </div>
                    )}

                    {canPerform('create') && type === 'confidential' && (
                        <button
                            onClick={() => setShowCreateModal(true)}
                            className="btn-primary"
                        >
                            <Plus className="h-4 w-4 mr-2" />
                            Create File
                        </button>
                    )}
                </div>
            </div>

            {/* Permissions Info */}
            <div className={`bg-${color}-50 border border-${color}-200 rounded-lg p-4`}>
                <div className="flex items-center">
                    <Shield className={`h-5 w-5 text-${color}-600 mr-3`} />
                    <div>
                        <h3 className={`text-sm font-medium text-${color}-800`}>
                            Your Permissions for {type}
                        </h3>
                        <p className={`text-sm text-${color}-700`}>
                            You can: {permissions.join(', ') || 'No access'}
                        </p>
                    </div>
                </div>
            </div>

            {/* Files Grid/List */}
            {files.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {files.map((file) => (
                        <div key={file.id} className="card p-6">
                            <div className="flex items-start justify-between mb-4">
                                <div className="flex items-center space-x-3">
                                    {getFileIcon()}
                                    <div className="min-w-0 flex-1">
                                        <h3 className="text-sm font-medium text-gray-900 truncate">
                                            {file.original_name}
                                        </h3>
                                        <p className="text-xs text-gray-500">
                                            Created {formatDate(file.created_at)}
                                        </p>
                                    </div>
                                </div>
                            </div>

                            {/* Actions */}
                            <div className="flex items-center space-x-2">
                                {canPerform('read') && (
                                    <button
                                        onClick={() => handleReadFile(file.id, file.original_name)}
                                        className={`text-${color}-600 hover:text-${color}-700 p-1 rounded`}
                                        title={type === 'confidential' ? 'Edit' : 'Download'}
                                    >
                                        {type === 'confidential' ? (
                                            <Edit className="h-4 w-4" />
                                        ) : (
                                            <Download className="h-4 w-4" />
                                        )}
                                    </button>
                                )}

                                {canPerform('delete') && (
                                    <button
                                        onClick={() => handleDeleteFile(file.id, file.original_name)}
                                        className="text-red-600 hover:text-red-700 p-1 rounded"
                                        title="Delete"
                                    >
                                        <Trash2 className="h-4 w-4" />
                                    </button>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            ) : (
                <div className="text-center py-12">
                    {getFileIcon()}
                    <h3 className="mt-2 text-sm font-medium text-gray-900">No {type} found</h3>
                    <p className="mt-1 text-sm text-gray-500">
                        {canPerform('create')
                            ? `Start by uploading your first ${type.slice(0, -1)}.`
                            : `You don't have permission to create ${type}.`
                        }
                    </p>
                </div>
            )}

            {/* Create Confidential File Modal */}
            {showCreateModal && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
                    <div className="bg-white rounded-lg p-6 w-full max-w-2xl">
                        <div className="flex items-center justify-between mb-4">
                            <h2 className="text-lg font-semibold text-gray-900">
                                Create Confidential File
                            </h2>
                            <button
                                onClick={() => setShowCreateModal(false)}
                                className="text-gray-400 hover:text-gray-600"
                            >
                                <X className="h-5 w-5" />
                            </button>
                        </div>

                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Filename
                                </label>
                                <input
                                    type="text"
                                    value={newFileName}
                                    onChange={(e) => setNewFileName(e.target.value)}
                                    className="input-field"
                                    placeholder="Enter filename (without extension)"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Content
                                </label>
                                <textarea
                                    value={newFileContent}
                                    onChange={(e) => setNewFileContent(e.target.value)}
                                    rows={10}
                                    className="input-field resize-none"
                                    placeholder="Enter file content..."
                                />
                            </div>
                        </div>

                        <div className="flex justify-end space-x-3 mt-6">
                            <button
                                onClick={() => setShowCreateModal(false)}
                                className="btn-secondary"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleCreateConfidentialFile}
                                className="btn-primary"
                            >
                                <Save className="h-4 w-4 mr-2" />
                                Create File
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Edit Confidential File Modal */}
            {showEditModal && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
                    <div className="bg-white rounded-lg p-6 w-full max-w-4xl h-5/6">
                        <div className="flex items-center justify-between mb-4">
                            <h2 className="text-lg font-semibold text-gray-900">
                                Edit: {editingFile?.name}
                            </h2>
                            <button
                                onClick={() => {
                                    setShowEditModal(false)
                                    setEditingFile(null)
                                    setEditContent('')
                                }}
                                className="text-gray-400 hover:text-gray-600"
                            >
                                <X className="h-5 w-5" />
                            </button>
                        </div>

                        <div className="h-full">
                            <textarea
                                value={editContent}
                                onChange={(e) => setEditContent(e.target.value)}
                                className="w-full h-4/5 p-4 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none font-mono text-sm"
                                placeholder="File content..."
                                readOnly={!canPerform('write')}
                            />
                        </div>

                        <div className="flex justify-end space-x-3 mt-4">
                            <button
                                onClick={() => {
                                    setShowEditModal(false)
                                    setEditingFile(null)
                                    setEditContent('')
                                }}
                                className="btn-secondary"
                            >
                                {canPerform('write') ? 'Cancel' : 'Close'}
                            </button>
                            {canPerform('write') && (
                                <button
                                    onClick={handleUpdateFile}
                                    className="btn-primary"
                                >
                                    <Save className="h-4 w-4 mr-2" />
                                    Save Changes
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* No Permissions Message */}
            {permissions.length === 0 && (
                <div className="text-center py-12">
                    <EyeOff className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900">No Access</h3>
                    <p className="text-gray-500">
                        You don't have permission to access {type} files.
                    </p>
                </div>
            )}
        </div>
    )
}