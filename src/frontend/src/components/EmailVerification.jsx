import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Mail, Check, Lock, AlertTriangle, Send, Clock, ArrowRight } from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'

export default function EmailVerification() {
    const [step, setStep] = useState(1)
    const [verificationCode, setVerificationCode] = useState('')
    const [loading, setLoading] = useState(false)
    const [emailSent, setEmailSent] = useState(false)
    const [maskedEmail, setMaskedEmail] = useState('')
    const navigate = useNavigate()

    const sendVerificationEmail = async () => {
        setLoading(true)
        try {
            const response = await axios.post('/send_verification_email')
            setMaskedEmail(response.data.email)
            setEmailSent(true)
            setStep(2)
            toast.success('Verification code sent to your email!')
        } catch (error) {
            toast.error('Failed to send verification email')
            console.error('Email verification error:', error)
        } finally {
            setLoading(false)
        }
    }

    const verifyEmailCode = async () => {
        if (verificationCode.length !== 6) {
            toast.error('Please enter a valid 6-digit code')
            return
        }

        setLoading(true)
        try {
            await axios.post('/verify_email_code', { code: verificationCode })
            toast.success('Email verification enabled successfully!')
            navigate('/dashboard')
        } catch (error) {
            const message = error.response?.data?.error || 'Invalid verification code'
            toast.error(message)
        } finally {
            setLoading(false)
        }
    }

    const handleCodeChange = (e) => {
        const value = e.target.value.replace(/\D/g, '').slice(0, 6)
        setVerificationCode(value)
    }

    const skipEmailVerification = () => {
        navigate('/dashboard')
    }

    const resendCode = () => {
        setVerificationCode('')
        sendVerificationEmail()
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 flex items-center justify-center p-4">
            <div className="max-w-2xl w-full bg-white rounded-3xl shadow-2xl p-8 border border-slate-200">
                {/* Header */}
                <div className="text-center mb-8">
                    <div className="flex justify-center mb-6">
                        <div className="bg-gradient-to-r from-blue-600 to-indigo-600 rounded-2xl p-4 shadow-lg">
                            <Mail className="h-12 w-12 text-white" />
                        </div>
                    </div>
                    <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent mb-2">
                        Email Verification Setup
                    </h1>
                    <p className="text-slate-600 text-lg">
                        Enhance your ForensicLink account security with email-based verification
                    </p>
                </div>

                {/* Security Notice */}
                <div className="mb-8 p-6 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-2xl border border-blue-100">
                    <div className="flex items-start">
                        <AlertTriangle className="h-6 w-6 text-blue-600 mr-3 mt-1 flex-shrink-0" />
                        <div>
                            <h3 className="text-lg font-semibold text-blue-800 mb-2">
                                Optional Security Enhancement
                            </h3>
                            <p className="text-blue-700 text-sm leading-relaxed">
                                Email verification is <strong>optional</strong> but highly recommended for ForensicLink.
                                When enabled, you'll receive verification codes via email for enhanced security when accessing
                                sensitive digital evidence and forensic data. You can enable it now or skip and set it up later.
                            </p>
                        </div>
                    </div>
                </div>

                {/* Step 1: Send Email */}
                {step === 1 && (
                    <div className="space-y-6">
                        <div className="text-center">
                            <div className="bg-blue-50 rounded-2xl p-8 mb-6">
                                <Send className="h-16 w-16 text-blue-600 mx-auto mb-4" />
                                <h3 className="text-xl font-semibold text-slate-800 mb-2">
                                    Send Verification Code
                                </h3>
                                <p className="text-slate-600">
                                    We'll send a 6-digit verification code to your registered email address.
                                </p>
                            </div>
                        </div>

                        <div className="flex justify-center space-x-4">
                            <button
                                onClick={sendVerificationEmail}
                                disabled={loading}
                                className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-semibold py-3 px-8 rounded-xl transition-all duration-200 transform hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-xl"
                            >
                                {loading ? (
                                    <div className="flex items-center">
                                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                                        Sending...
                                    </div>
                                ) : (
                                    <div className="flex items-center">
                                        <Send className="h-5 w-5 mr-2" />
                                        Send Verification Code
                                    </div>
                                )}
                            </button>
                            <button
                                onClick={skipEmailVerification}
                                className="bg-slate-200 hover:bg-slate-300 text-slate-700 font-semibold py-3 px-8 rounded-xl transition-all duration-200"
                            >
                                Skip for Now
                            </button>
                        </div>
                    </div>
                )}

                {/* Step 2: Verify Code */}
                {step === 2 && (
                    <div className="space-y-6">
                        <div className="text-center">
                            <div className="bg-green-50 rounded-2xl p-8 mb-6">
                                <Clock className="h-16 w-16 text-green-600 mx-auto mb-4" />
                                <h3 className="text-xl font-semibold text-slate-800 mb-2">
                                    Enter Verification Code
                                </h3>
                                <p className="text-slate-600 mb-2">
                                    We've sent a 6-digit code to:
                                </p>
                                <p className="text-blue-600 font-semibold text-lg">
                                    {maskedEmail}
                                </p>
                                <p className="text-slate-500 text-sm mt-2">
                                    Code expires in 10 minutes
                                </p>
                            </div>
                        </div>

                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-semibold text-slate-700 mb-2 text-center">
                                    Verification Code
                                </label>
                                <input
                                    type="text"
                                    value={verificationCode}
                                    onChange={handleCodeChange}
                                    className="w-full text-center text-3xl tracking-[0.5em] font-mono py-4 px-6 border-2 border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 bg-slate-50"
                                    placeholder="000000"
                                    maxLength={6}
                                    autoComplete="off"
                                />
                            </div>

                            <div className="flex justify-center space-x-4">
                                <button
                                    onClick={resendCode}
                                    disabled={loading}
                                    className="bg-slate-200 hover:bg-slate-300 text-slate-700 font-semibold py-3 px-6 rounded-xl transition-all duration-200"
                                >
                                    Resend Code
                                </button>
                                <button
                                    onClick={verifyEmailCode}
                                    disabled={verificationCode.length !== 6 || loading}
                                    className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white font-semibold py-3 px-8 rounded-xl transition-all duration-200 transform hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-xl"
                                >
                                    {loading ? (
                                        <div className="flex items-center">
                                            <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                                            Verifying...
                                        </div>
                                    ) : (
                                        <div className="flex items-center">
                                            <Check className="h-5 w-5 mr-2" />
                                            Verify & Enable
                                        </div>
                                    )}
                                </button>
                            </div>

                            <div className="text-center">
                                <button
                                    onClick={skipEmailVerification}
                                    className="text-slate-500 hover:text-slate-700 text-sm font-medium transition-colors"
                                >
                                    Skip and go to dashboard
                                </button>
                            </div>
                        </div>
                    </div>
                )}

                {/* Security Benefits */}
                <div className="mt-8 p-6 bg-gradient-to-r from-emerald-50 to-green-50 rounded-2xl border border-emerald-100">
                    <h4 className="text-lg font-semibold text-emerald-800 mb-3 flex items-center">
                        <Shield className="h-5 w-5 mr-2" />
                        Security Benefits
                    </h4>
                    <ul className="text-sm text-emerald-700 space-y-2">
                        <li className="flex items-start">
                            <ArrowRight className="h-4 w-4 mr-2 mt-0.5 flex-shrink-0" />
                            Enhanced protection for sensitive forensic evidence
                        </li>
                        <li className="flex items-start">
                            <ArrowRight className="h-4 w-4 mr-2 mt-0.5 flex-shrink-0" />
                            Email-based verification codes for secure access
                        </li>
                        <li className="flex items-start">
                            <ArrowRight className="h-4 w-4 mr-2 mt-0.5 flex-shrink-0" />
                            No additional apps required - uses your email
                        </li>
                        <li className="flex items-start">
                            <ArrowRight className="h-4 w-4 mr-2 mt-0.5 flex-shrink-0" />
                            Can be enabled or disabled anytime from settings
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    )
}
