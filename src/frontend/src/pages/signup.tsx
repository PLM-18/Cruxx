import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useTheme } from '../context/ThemeContext'
import logo from '../../../../assets/Logo_Cruxx.png'
import { Eye, EyeOff, Mail, Lock, User, Sun, Moon } from 'lucide-react'

interface FormData {
    name: string
    surname: string
    email: string
    password: string
    confirmPassword: string
}

export default function Signup(): React.ReactElement {
    const [formData, setFormData] = useState<FormData>({
        name: '',
        surname: '',
        email: '',
        password: '',
        confirmPassword: ''
    })
    const [showPassword, setShowPassword] = useState<boolean>(false)
    const [showConfirmPassword, setShowConfirmPassword] = useState<boolean>(false)
    const [loading, setLoading] = useState<boolean>(false)
    const [passwordError, setPasswordError] = useState<string>('')
    const { register } = useAuth()
    const { theme, toggleTheme } = useTheme()
    const navigate = useNavigate()

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>): void => {
        const { name, value } = e.target
        setFormData({
            ...formData,
            [name]: value
        })

        // Clear password error when user types
        if (name === 'password' || name === 'confirmPassword') {
            setPasswordError('')
        }
    }

    const validatePasswords = (): boolean => {
        if (formData.password !== formData.confirmPassword) {
            setPasswordError('Passwords do not match')
            return false
        }
        if (formData.password.length < 8) {
            setPasswordError('Password must be at least 8 characters long')
            return false
        }
        return true
    }

    const handleSubmit = async (e: React.FormEvent<HTMLFormElement>): Promise<void> => {
        e.preventDefault()
        
        if (!validatePasswords()) {
            return
        }

        setLoading(true)

        try {
            await register({
                name: formData.name,
                surname: formData.surname,
                email: formData.email,
                password: formData.password
            })
            
            navigate('/login')
        } catch (error) {
            // Error handling is done in the context
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
            {/* Theme Toggle Button */}
            <button
                onClick={toggleTheme}
                className="fixed top-4 right-4 p-3 rounded-full bg-white dark:bg-gray-800 shadow-lg hover:shadow-xl transition-all duration-200 border border-gray-200 dark:border-gray-700"
                aria-label="Toggle theme"
            >
                {theme === 'dark' ? (
                    <Sun className="h-5 w-5 text-yellow-500" />
                ) : (
                    <Moon className="h-5 w-5 text-gray-600" />
                )}
            </button>

            <div className="max-w-5xl w-full mx-4">
                <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl overflow-hidden border border-gray-100 dark:border-gray-700">
                    <div className="flex min-h-[650px]">
                        {/* Left side - Logo */}
                        <div className="flex-1 bg-gradient-to-br from-green-600 to-emerald-700 dark:from-green-700 dark:to-emerald-800 flex items-center justify-center p-8">
                            <div className="text-center">
                                <img src={logo} className="h-24 w-24 mx-auto mb-4" alt="Site logo" />
                                <h2 className="text-2xl font-bold text-white mb-3">Join Us Today</h2>
                                <p className="text-green-100">Create your account and start your journey</p>
                            </div>
                        </div>

                        {/* Right side - Signup Form */}
                        <div className="flex-1 p-8 bg-white dark:bg-gray-900 transition-colors duration-200">
                            {/* Header */}
                            <div className="mb-6">
                                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Create Account</h2>
                                <p className="text-gray-500 dark:text-gray-400">Fill in your details to get started</p>
                            </div>

                            {/* Form */}
                            <form onSubmit={handleSubmit} className="space-y-5">
                                {/* Name and Surname Row */}
                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                                            Name
                                        </label>
                                        <div className="relative">
                                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                                <User className="h-5 w-5 text-gray-400 dark:text-gray-500" />
                                            </div>
                                            <input
                                                type="text"
                                                name="name"
                                                value={formData.name}
                                                onChange={handleChange}
                                                required
                                                className="input-field pl-12 text-base"
                                                placeholder="Enter your name"
                                            />
                                        </div>
                                    </div>

                                    <div>
                                        <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                                            Surname
                                        </label>
                                        <div className="relative">
                                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                                <User className="h-5 w-5 text-gray-400 dark:text-gray-500" />
                                            </div>
                                            <input
                                                type="text"
                                                name="surname"
                                                value={formData.surname}
                                                onChange={handleChange}
                                                required
                                                className="input-field pl-12 text-base"
                                                placeholder="Enter your surname"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* Email */}
                                <div>
                                    <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                                        Email Address
                                    </label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                            <Mail className="h-5 w-5 text-gray-400 dark:text-gray-500" />
                                        </div>
                                        <input
                                            type="email"
                                            name="email"
                                            value={formData.email}
                                            onChange={handleChange}
                                            required
                                            className="input-field pl-12 text-base"
                                            placeholder="Enter your email address"
                                        />
                                    </div>
                                </div>

                                {/* Password */}
                                <div>
                                    <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                                        Password
                                    </label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                            <Lock className="h-5 w-5 text-gray-400 dark:text-gray-500" />
                                        </div>
                                        <input
                                            type={showPassword ? 'text' : 'password'}
                                            name="password"
                                            value={formData.password}
                                            onChange={handleChange}
                                            required
                                            className="input-field pl-12 pr-12 text-base"
                                            placeholder="Create a strong password"
                                        />
                                        <button
                                            type="button"
                                            className="absolute inset-y-0 right-0 pr-4 flex items-center hover:bg-gray-50 dark:hover:bg-gray-800 rounded-r-lg transition-colors duration-200"
                                            onClick={() => setShowPassword(!showPassword)}
                                        >
                                            {showPassword ? (
                                                <EyeOff className="h-5 w-5 text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300" />
                                            ) : (
                                                <Eye className="h-5 w-5 text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300" />
                                            )}
                                        </button>
                                    </div>
                                </div>

                                {/* Confirm Password */}
                                <div>
                                    <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                                        Confirm Password
                                    </label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                            <Lock className="h-5 w-5 text-gray-400 dark:text-gray-500" />
                                        </div>
                                        <input
                                            type={showConfirmPassword ? 'text' : 'password'}
                                            name="confirmPassword"
                                            value={formData.confirmPassword}
                                            onChange={handleChange}
                                            required
                                            className="input-field pl-12 pr-12 text-base"
                                            placeholder="Confirm your password"
                                        />
                                        <button
                                            type="button"
                                            className="absolute inset-y-0 right-0 pr-4 flex items-center hover:bg-gray-50 dark:hover:bg-gray-800 rounded-r-lg transition-colors duration-200"
                                            onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                        >
                                            {showConfirmPassword ? (
                                                <EyeOff className="h-5 w-5 text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300" />
                                            ) : (
                                                <Eye className="h-5 w-5 text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300" />
                                            )}
                                        </button>
                                    </div>
                                    {passwordError && (
                                        <p className="mt-2 text-sm text-red-600 dark:text-red-400">{passwordError}</p>
                                    )}
                                </div>

                                <div className="pt-2">
                                    <button
                                        type="submit"
                                        disabled={loading}
                                        className="w-full btn-primary disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                                    >
                                        {loading ? (
                                            <div className="flex items-center justify-center">
                                                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3"></div>
                                                Creating account...
                                            </div>
                                        ) : (
                                            'Create Account'
                                        )}
                                    </button>
                                </div>
                            </form>

                            {/* Footer */}
                            <div className="mt-6 text-center">
                                <p className="text-gray-600 dark:text-gray-400">
                                    Already have an account?{' '}
                                    <Link
                                        to="/login"
                                        className="font-semibold text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300 transition-colors duration-200"
                                    >
                                        Sign in
                                    </Link>
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}