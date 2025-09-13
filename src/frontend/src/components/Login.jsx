import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Shield, Eye, EyeOff, Mail, Lock, Search, Database, FileText } from 'lucide-react'
import toast from 'react-hot-toast'

export default function Login() {
    const [formData, setFormData] = useState({
        email: '',
        password: ''
    })
    const [showPassword, setShowPassword] = useState(false)
    const [loading, setLoading] = useState(false)
    const { login } = useAuth()
    const navigate = useNavigate()

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        })
    }

    const handleSubmit = async (e) => {
        e.preventDefault()
        setLoading(true)

        console.log('🔐 Login attempt:', { email: formData.email, password: '***' })

        try {
            const result = await login(formData.email, formData.password)
            console.log('✅ Login result:', result)
            
            if (result?.requiresMFA) {
                console.log('🔒 MFA required, redirecting to verification')
                navigate('/mfa-verify')
            } else {
                console.log('🎉 Login successful, redirecting to dashboard')
                navigate('/dashboard')
            }
        } catch (error) {
            console.error('❌ Login error:', error)
            console.error('Error details:', {
                message: error.message,
                response: error.response?.data,
                status: error.response?.status
            })
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 relative overflow-hidden">
            {/* Background Pattern */}
            <div className="absolute inset-0 opacity-5">
                <div className="h-full w-full bg-white bg-opacity-5" style={{
                    backgroundImage: `radial-gradient(circle at 1px 1px, rgba(255,255,255,0.15) 1px, transparent 0)`,
                    backgroundSize: '20px 20px'
                }}></div>
            </div>
            
            {/* Floating Elements */}
            <div className="absolute top-20 left-20 text-blue-400/20">
                <Database className="h-16 w-16 animate-pulse" />
            </div>
            <div className="absolute top-40 right-32 text-indigo-400/20">
                <Search className="h-12 w-12 animate-bounce" />
            </div>
            <div className="absolute bottom-32 left-32 text-slate-400/20">
                <FileText className="h-14 w-14 animate-pulse" />
            </div>

            <div className="max-w-md w-full mx-4 relative z-10">
                <div className="bg-white/95 backdrop-blur-sm rounded-3xl shadow-2xl p-8 border border-white/20">
                    {/* Header */}
                    <div className="text-center mb-8">
                        <div className="flex justify-center mb-6">
                            <div className="relative">
                                <div className="bg-gradient-to-r from-blue-600 to-indigo-600 rounded-2xl p-4 shadow-lg">
                                    <Shield className="h-10 w-10 text-white" />
                                </div>
                                <div className="absolute -top-1 -right-1 bg-green-500 rounded-full p-1">
                                    <Search className="h-4 w-4 text-white" />
                                </div>
                            </div>
                        </div>
                        <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent mb-2">
                            ForensicLink
                        </h1>
                        <p className="text-slate-600 text-lg font-medium">Digital Evidence Collaboration Platform</p>
                        <p className="text-slate-500 text-sm mt-1">Secure • Collaborative • Professional</p>
                    </div>

                    {/* Form */}
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div>
                            <label className="block text-sm font-semibold text-slate-700 mb-2">
                                Email Address
                            </label>
                            <div className="relative">
                                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                    <Mail className="h-5 w-5 text-slate-400" />
                                </div>
                                <input
                                    type="email"
                                    name="email"
                                    value={formData.email}
                                    onChange={handleChange}
                                    required
                                    className="w-full pl-12 pr-4 py-3 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 bg-slate-50/50 hover:bg-white"
                                    placeholder="investigator@forensiclink.com"
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-semibold text-slate-700 mb-2">
                                Password
                            </label>
                            <div className="relative">
                                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                    <Lock className="h-5 w-5 text-slate-400" />
                                </div>
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    name="password"
                                    value={formData.password}
                                    onChange={handleChange}
                                    required
                                    className="w-full pl-12 pr-12 py-3 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 bg-slate-50/50 hover:bg-white"
                                    placeholder="Enter your secure password"
                                />
                                <button
                                    type="button"
                                    className="absolute inset-y-0 right-0 pr-4 flex items-center text-slate-400 hover:text-slate-600 transition-colors"
                                    onClick={() => setShowPassword(!showPassword)}
                                >
                                    {showPassword ? (
                                        <EyeOff className="h-5 w-5" />
                                    ) : (
                                        <Eye className="h-5 w-5" />
                                    )}
                                </button>
                            </div>
                        </div>

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-semibold py-3 px-6 rounded-xl transition-all duration-200 transform hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none shadow-lg hover:shadow-xl"
                        >
                            {loading ? (
                                <div className="flex items-center justify-center">
                                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                                    Authenticating...
                                </div>
                            ) : (
                                <div className="flex items-center justify-center">
                                    <Shield className="h-5 w-5 mr-2" />
                                    Access ForensicLink
                                </div>
                            )}
                        </button>
                    </form>

                    {/* Footer */}
                    <div className="mt-8 text-center">
                        <p className="text-slate-600">
                            New to ForensicLink?{' '}
                            <Link
                                to="/register"
                                className="font-semibold text-blue-600 hover:text-blue-700 transition-colors"
                            >
                                Create Account
                            </Link>
                        </p>
                    </div>

                    {/* Security Notice */}
                    <div className="mt-6 p-4 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl border border-blue-100">
                        <div className="flex items-center">
                            <Shield className="h-5 w-5 text-blue-600 mr-2" />
                            <p className="text-sm text-blue-800 font-medium">
                                Secure Evidence Collaboration Platform
                            </p>
                        </div>
                        <p className="text-xs text-blue-600 mt-1">
                            Built for cybersecurity professionals and digital forensics investigators
                        </p>
                    </div>
                </div>
            </div>
        </div>
    )
}