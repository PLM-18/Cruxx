import React, { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import axios from 'axios'
import { toast } from 'react-toastify'

const RegistrationEmailVerification = () => {
    const navigate = useNavigate()
    const location = useLocation()
    const { userId, email } = location.state || {}

    const [verificationCode, setVerificationCode] = useState('')
    const [loading, setLoading] = useState(false)
    const [resending, setResending] = useState(false)

    if (!userId || !email) {
        navigate('/register')
        return null
    }

    const handleVerification = async (e) => {
        e.preventDefault()

        if (!verificationCode || verificationCode.length !== 6) {
            toast.error('Please enter a valid 6-digit verification code')
            return
        }

        setLoading(true)

        try {
            console.log('🔐 Verifying registration email with code:', verificationCode)

            const response = await axios.post('/verify_registration_email', {
                userId,
                code: verificationCode
            })

            console.log('✅ Email verification successful:', response.data)
            toast.success('Email verified successfully! Your account is pending admin approval.')
            navigate('/login')
        } catch (error) {
            console.error('❌ Email verification failed:', error)
            const message = error.response?.data?.error || 'Verification failed'
            toast.error(message)
        } finally {
            setLoading(false)
        }
    }

    const handleResendCode = async () => {
        setResending(true)

        try {
            // We'll need to create a resend endpoint or modify the registration to resend
            toast.info('Please register again to receive a new verification code')
            navigate('/register')
        } catch (error) {
            toast.error('Failed to resend verification code')
        } finally {
            setResending(false)
        }
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 relative overflow-hidden">
            {/* Background Pattern */}
            <div className="absolute inset-0 opacity-5">
                <div className="h-full w-full bg-white bg-opacity-5" style={{
                    backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.1'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`
                }}></div>
            </div>

            <div className="relative z-10 w-full max-w-md">
                <div className="bg-white/10 backdrop-blur-md rounded-2xl shadow-2xl border border-white/20 p-8">
                    {/* Header */}
                    <div className="text-center mb-8">
                        <div className="flex items-center justify-center mb-4">
                            <div className="w-12 h-12 bg-gradient-to-r from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center">
                                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                </svg>
                            </div>
                        </div>
                        <h1 className="text-3xl font-bold text-white mb-2">Verify Your Email</h1>
                        <p className="text-blue-200">
                            We've sent a 6-digit verification code to
                        </p>
                        <p className="text-white font-semibold">{email}</p>
                    </div>

                    {/* Verification Form */}
                    <form onSubmit={handleVerification} className="space-y-6">
                        <div>
                            <label htmlFor="verificationCode" className="block text-sm font-medium text-blue-200 mb-2">
                                Verification Code
                            </label>
                            <input
                                id="verificationCode"
                                name="verificationCode"
                                type="text"
                                maxLength="6"
                                placeholder="Enter 6-digit code"
                                value={verificationCode}
                                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ''))}
                                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-2xl tracking-widest"
                                required
                            />
                        </div>

                        <button
                            type="submit"
                            disabled={loading || verificationCode.length !== 6}
                            className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-3 px-4 rounded-lg font-semibold hover:from-blue-700 hover:to-indigo-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-transparent transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {loading ? (
                                <div className="flex items-center justify-center">
                                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                                    Verifying...
                                </div>
                            ) : (
                                'Verify Email'
                            )}
                        </button>
                    </form>

                    {/* Resend Code */}
                    <div className="mt-6 text-center">
                        <p className="text-blue-200 text-sm mb-2">
                            Didn't receive the code?
                        </p>
                        <button
                            onClick={handleResendCode}
                            disabled={resending}
                            className="text-blue-400 hover:text-blue-300 font-medium text-sm underline disabled:opacity-50"
                        >
                            {resending ? 'Resending...' : 'Resend verification code'}
                        </button>
                    </div>

                    {/* Back to Login */}
                    <div className="mt-8 text-center">
                        <button
                            onClick={() => navigate('/login')}
                            className="text-blue-400 hover:text-blue-300 font-medium text-sm"
                        >
                            ← Back to Login
                        </button>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default RegistrationEmailVerification
