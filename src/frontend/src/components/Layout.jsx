import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import {
    Home,
    Users,
    FileText,
    Image,
    Shield,
    BarChart3,
    LogOut,
    Menu,
    X,
    Briefcase,
    Trophy
} from 'lucide-react'
import { useState } from 'react'

export default function Layout() {
    const { user, logout } = useAuth()
    const navigate = useNavigate()
    const [sidebarOpen, setSidebarOpen] = useState(false)

    const handleLogout = () => {
        logout()
        navigate('/login')
    }

    const navigation = [
        { name: 'Dashboard', href: '/dashboard', icon: Home },
        { name: 'Workspaces', href: '/workspaces', icon: Briefcase },
        { name: 'Achievements', href: '/gamification', icon: Trophy },
        // { name: 'Images', href: '/files/images', icon: Image },
        // { name: 'Documents', href: '/files/documents', icon: FileText },
        // { name: 'Confidential', href: '/files/confidential', icon: Shield },
    ]

    if (user.role === 'Admin' || user.role === 'Manager') {
        navigation.push(
            { name: 'Manage Users', href: '/manage-users', icon: Users },
            { name: 'Analytics', href: '/analytics', icon: BarChart3 }
        )
    }

    return (
        <div className="flex h-screen bg-gray-100">
            {/* Mobile sidebar overlay */}
            {sidebarOpen && (
                <div
                    className="fixed inset-0 z-40 lg:hidden"
                    onClick={() => setSidebarOpen(false)}
                >
                    <div className="absolute inset-0 bg-gray-600 opacity-75"></div>
                </div>
            )}

            {/* Sidebar */}
            <div className={`fixed inset-y-0 left-0 z-50 w-64 bg-white shadow-lg transform ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0`}>
                <div className="flex items-center justify-between h-16 px-4 border-b">
                    <div className="flex items-center space-x-2">
                        <Shield className="h-8 w-8 text-blue-600" />
                        <span className="font-bold text-xl text-gray-900">Forensic-Link</span>

                    </div>
                    <button
                        className="lg:hidden"
                        onClick={() => setSidebarOpen(false)}
                    >
                        <X className="h-6 w-6" />
                    </button>
                </div>

                <nav className="mt-8">
                    <div className="px-4 mb-4">
                        <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                            Navigation
                        </div>
                    </div>

                    {navigation.map((item) => (
                        <NavLink
                            key={item.name}
                            to={item.href}
                            className={({ isActive }) =>
                                `flex items-center px-4 py-3 text-sm font-medium transition-colors ${isActive
                                    ? 'bg-blue-50 text-blue-700 border-r-2 border-blue-600'
                                    : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                                }`
                            }
                            onClick={() => setSidebarOpen(false)}
                        >
                            <item.icon className="mr-3 h-5 w-5" />
                            {item.name}
                        </NavLink>
                    ))}
                </nav>

                <div className="absolute bottom-0 left-0 right-0 p-4 border-t">
                    <div className="flex items-center space-x-3 mb-3">
                        <div className="flex-shrink-0">
                            <div className="h-8 w-8 bg-blue-600 rounded-full flex items-center justify-center">
                                <span className="text-white text-sm font-medium">
                                    {user.name[0]}{user.surname[0]}
                                </span>
                            </div>
                        </div>
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-gray-900 truncate">
                                {user.name} {user.surname}
                            </p>
                            <p className="text-xs text-gray-500 truncate">
                                {user.role}
                            </p>
                        </div>
                    </div>
                    <button
                        onClick={handleLogout}
                        className="flex items-center w-full px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 hover:text-gray-900 rounded-md transition-colors"
                    >
                        <LogOut className="mr-2 h-4 w-4" />
                        Sign out
                    </button>
                </div>
            </div>

            {/* Main content */}
            <div className="flex-1 flex flex-col overflow-hidden">
                {/* Top header */}
                <header className="bg-white shadow-sm border-b border-gray-200">
                    <div className="flex items-center justify-between h-16 px-4">
                        <div className="flex items-center">
                            <button
                                className="lg:hidden mr-4"
                                onClick={() => setSidebarOpen(true)}
                            >
                                <Menu className="h-6 w-6 text-gray-600" />
                            </button>
                            <h1 className="text-lg font-semibold text-gray-900">
                                Welcome back, {user.name}!
                            </h1>
                        </div>

                        <div className="flex items-center space-x-4">
                            <div className="text-sm text-gray-500">
                                Role: <span className="font-medium text-gray-900">{user.role}</span>
                            </div>
                        </div>
                    </div>
                </header>

                {/* Page content */}
                <main className="flex-1 overflow-auto">
                    <div className="p-6">
                        <Outlet />
                    </div>
                </main>
            </div>
        </div>
    )
}