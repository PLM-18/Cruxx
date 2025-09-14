import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Mail, Check, Lock, AlertTriangle, Send, Clock } from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'

export default function EmailVerificationSetup() {
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

    const steps = [
        {
            title: 'Install Authenticator App',
            description: 'Download and install an authenticator app like Google Authenticator or Authy'
        },
        {
            title: 'Scan QR Code',
            description: 'Open your authenticator app and scan the QR code below'
        },
        {
            title: 'Verify Setup',
            description: 'Enter the 6-digit code from your authenticator app'
        }
    ]

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

                {/* Progress Steps */}
                <div className="mb-8">
                    <div className="flex items-center justify-center space-x-4">
                        {steps.map((stepItem, index) => (
                            <div key={index} className="flex items-center">
                                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${step > index + 1
                                    ? 'bg-green-600 text-white'
                                    : step === index + 1
                                        ? 'bg-blue-600 text-white'
                                        : 'bg-gray-200 text-gray-600'
                                    }`}>
                                    {step > index + 1 ? <Check className="h-4 w-4" /> : index + 1}
                                </div>
                                {index < steps.length - 1 && (
                                    <div className={`w-16 h-1 mx-2 ${step > index + 1 ? 'bg-green-600' : 'bg-gray-200'
                                        }`}></div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>

                {/* Step Content */}
                <div className="space-y-6">
                    {/* Step 1: Install App */}
                    {step === 1 && (
                        <div className="text-center">
                            <div className="bg-gray-100 rounded-lg p-6 mb-6">
                                <Smartphone className="h-16 w-16 text-gray-600 mx-auto mb-4" />
                                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                                    Install an Authenticator App
                                </h3>
                                <p className="text-gray-600 mb-4">
                                    Download one of these popular authenticator apps on your mobile device:
                                </p>
                                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                    <div className="bg-white rounded-lg p-4 border">
                                        <h4 className="font-medium text-gray-900">Google Authenticator</h4>
                                        <p className="text-sm text-gray-600">iOS & Android</p>
                                    </div>
                                    <div className="bg-white rounded-lg p-4 border">
                                        <h4 className="font-medium text-gray-900">Authy</h4>
                                        <p className="text-sm text-gray-600">iOS & Android</p>
                                    </div>
                                    <div className="bg-white rounded-lg p-4 border">
                                        <h4 className="font-medium text-gray-900">Microsoft Authenticator</h4>
                                        <p className="text-sm text-gray-600">iOS & Android</p>
                                    </div>
                                </div>
                            </div>
                            <button
                                onClick={() => setStep(2)}
                                className="btn-primary"
                            >
                                I've installed the app
                            </button>
                        </div>
                    )}

                    {/* Step 2: Scan QR Code */}
                    {step === 2 && (
                        <div className="text-center">
                            <h3 className="text-lg font-semibold text-gray-900 mb-4">
                                Scan this QR code with your authenticator app
                            </h3>

                            {qrCode ? (
                                <div className="bg-white rounded-lg border-2 border-gray-200 p-6 inline-block mb-6">
                                    <img src={qrCode} alt="QR Code" className="w-48 h-48 mx-auto" />
                                </div>
                            ) : (
                                <div className="bg-gray-100 rounded-lg p-12 mb-6">
                                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
                                </div>
                            )}

                            <div className="bg-gray-50 rounded-lg p-4 mb-6">
                                <h4 className="text-sm font-medium text-gray-900 mb-2">
                                    Can't scan the QR code?
                                </h4>
                                <p className="text-xs text-gray-600 mb-2">
                                    Enter this code manually in your authenticator app:
                                </p>
                                <code className="bg-white px-2 py-1 rounded text-sm font-mono border">
                                    {secret}
                                </code>
                            </div>

                            <div className="flex justify-center space-x-4">
                                <button
                                    onClick={() => setStep(1)}
                                    className="btn-secondary"
                                >
                                    Back
                                </button>
                                <button
                                    onClick={() => setStep(3)}
                                    className="btn-primary"
                                    disabled={!qrCode}
                                >
                                    I've added the account
                                </button>
                            </div>
                        </div>
                    )}

                    {/* Step 3: Verify */}
                    {step === 3 && (
                        <div className="text-center">
                            <h3 className="text-lg font-semibold text-gray-900 mb-4">
                                Enter verification code
                            </h3>
                            <p className="text-gray-600 mb-6">
                                Enter the 6-digit code shown in your authenticator app
                            </p>

                            <div className="max-w-xs mx-auto mb-6">
                                <input
                                    type="text"
                                    value={verificationCode}
                                    onChange={handleCodeChange}
                                    className="input-field text-center text-2xl tracking-widest font-mono"
                                    placeholder="000000"
                                    maxLength={6}
                                    autoComplete="off"
                                />
                            </div>

                            <div className="flex justify-center space-x-4">
                                <button
                                    onClick={() => setStep(2)}
                                    className="btn-secondary"
                                >
                                    Back
                                </button>
                                <button
                                    onClick={verifyMFASetup}
                                    disabled={verificationCode.length !== 6 || loading}
                                    className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    {loading ? (
                                        <div className="flex items-center">
                                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                                            Verifying...
                                        </div>
                                    ) : (
                                        'Enable MFA'
                                    )}
                                </button>
                            </div>
                        </div>
                    )}
                </div>

                {/* Important Notes */}
                <div className="mt-8 p-4 bg-yellow-50 rounded-lg border border-yellow-200">
                    <h4 className="text-sm font-medium text-yellow-800 mb-2">
                        Important Security Notes:
                    </h4>
                    <ul className="text-xs text-yellow-700 space-y-1">
                        <li>• Keep your device secure and don't share your authenticator app</li>
                        <li>• Save backup codes in a secure location (if provided by your app)</li>
                        <li>• Contact your administrator if you lose access to your device</li>
                    </ul>
                </div>
            </div>
        </div>
    )
}