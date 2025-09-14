import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import toast from 'react-hot-toast'

// Components
import Login from './components/Login'
import Register from './components/Register'
import Dashboard from './components/Dashboard'
import EmailVerification from './components/EmailVerification'
import MFAVerify from './components/MFAVerify'
import ManageUsers from './components/ManageUsers'
import FileManager from './components/FileManager'
import Analytics from './components/Analytics'
import WorkspaceManager from './components/WorkspaceManager'
import WorkspaceDetail from './components/WorkspaceDetail'
import GamificationProfile from './components/GamificationProfile'
import Layout from './components/Layout'

// Context
import { AuthProvider, useAuth } from './context/AuthContext'

function AppRoutes() {
    const { user, loading } = useAuth()

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
            </div>
        )
    }

    return (
        <Routes>
            {!user ? (
                <>
                    <Route path="/login" element={<Login />} />
                    <Route path="/register" element={<Register />} />
                    <Route path="/email-verification" element={<EmailVerification />} />
                    <Route path="/mfa-verify" element={<MFAVerify />} />
                    <Route path="*" element={<Navigate to="/login" replace />} />
                </>
            ) : (
                <Route path="/" element={<Layout />}>
                    <Route index element={<Dashboard />} />
                    <Route path="dashboard" element={<Dashboard />} />
                    <Route path="workspaces" element={<WorkspaceManager />} />
                    <Route path="workspaces/:id" element={<WorkspaceDetail />} />
                    <Route path="gamification" element={<GamificationProfile />} />
                    <Route path="mfa-setup" element={<EmailVerification />} />
                    <Route path="files/:type" element={<FileManager />} />
                    <Route path="manage-users" element={<ManageUsers />} />
                    <Route path="analytics" element={<Analytics />} />
                    <Route path="*" element={<Navigate to="/" replace />} />
                </Route>
            )}
        </Routes>
    )
}

function App() {
    return (
        <AuthProvider>
            <Router>
                <div className="min-h-screen bg-gray-50">
                    <AppRoutes />
                </div>
            </Router>
        </AuthProvider>
    )
}

export default App