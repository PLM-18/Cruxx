import { useState, useEffect } from 'react'
import {
    BarChart,
    Bar,
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ResponsiveContainer,
    PieChart,
    Pie,
    Cell
} from 'recharts'
import {
    Activity,
    AlertTriangle,
    Shield,
    Users,
    Globe,
    Clock,
    TrendingUp,
    AlertCircle,
    CheckCircle,
    XCircle
} from 'lucide-react'
import axios from 'axios'
import toast from 'react-hot-toast'

export default function Analytics() {
    const [data, setData] = useState({
        logs: [],
        anomalies: [],
        statistics: {}
    })
    const [loading, setLoading] = useState(true)
    const [selectedTimeRange, setSelectedTimeRange] = useState('24h')

    useEffect(() => {
        fetchAnalytics()
    }, [selectedTimeRange])

    const fetchAnalytics = async () => {
        setLoading(true)
        try {
            const response = await axios.get('/analytics')
            setData(response.data)
        } catch (error) {
            toast.error('Failed to fetch analytics data')
        } finally {
            setLoading(false)
        }
    }

    const formatTimestamp = (timestamp) => {
        return new Date(timestamp).toLocaleString()
    }

    const getHourlyData = () => {
        const hours = Array.from({ length: 24 }, (_, i) => ({
            hour: `${i.toString().padStart(2, '0')}:00`,
            requests: data.statistics.hourlyActivity?.[i] || 0
        }))
        return hours
    }

    const getEndpointData = () => {
        if (!data.statistics.endpointStats) return []

        return Object.entries(data.statistics.endpointStats).map(([endpoint, stats]) => ({
            endpoint: endpoint.replace(/^\//, '') || 'root',
            total: stats.total,
            success: stats.success,
            failed: stats.failed,
            successRate: ((stats.success / stats.total) * 100).toFixed(1)
        }))
    }

    const getAnomalyData = () => {
        const severityCounts = {
            High: 0,
            Medium: 0,
            Low: 0
        }

        data.anomalies.forEach(anomaly => {
            severityCounts[anomaly.severity] = (severityCounts[anomaly.severity] || 0) + 1
        })

        return Object.entries(severityCounts).map(([severity, count]) => ({
            severity,
            count,
            color: severity === 'High' ? '#ef4444' : severity === 'Medium' ? '#f59e0b' : '#10b981'
        }))
    }

    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'High':
                return 'text-red-600 bg-red-100'
            case 'Medium':
                return 'text-yellow-600 bg-yellow-100'
            case 'Low':
                return 'text-green-600 bg-green-100'
            default:
                return 'text-gray-600 bg-gray-100'
        }
    }

    const getStatusIcon = (success) => {
        return success ? (
            <CheckCircle className="h-4 w-4 text-green-600" />
        ) : (
            <XCircle className="h-4 w-4 text-red-600" />
        )
    }

    if (loading) {
        return (
            <div className="flex justify-center items-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        )
    }

    const stats = data.statistics
    const hourlyData = getHourlyData()
    const endpointData = getEndpointData()
    const anomalyData = getAnomalyData()

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">System Analytics</h1>
                    <p className="text-gray-600">
                        Monitor system activity, detect anomalies, and analyze security patterns
                    </p>
                </div>
                <div className="flex items-center space-x-3">
                    <select
                        value={selectedTimeRange}
                        onChange={(e) => setSelectedTimeRange(e.target.value)}
                        className="input-field w-auto"
                    >
                        <option value="1h">Last Hour</option>
                        <option value="24h">Last 24 Hours</option>
                        <option value="7d">Last 7 Days</option>
                        <option value="30d">Last 30 Days</option>
                    </select>
                    <button
                        onClick={fetchAnalytics}
                        className="btn-primary"
                    >
                        <Activity className="h-4 w-4 mr-2" />
                        Refresh
                    </button>
                </div>
            </div>

            {/* Key Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
                <div className="card p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm text-gray-600">Total Requests</p>
                            <p className="text-3xl font-bold text-gray-900">{stats.totalRequests || 0}</p>
                        </div>
                        <Activity className="h-8 w-8 text-blue-600" />
                    </div>
                </div>

                <div className="card p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm text-gray-600">Success Rate</p>
                            <p className="text-3xl font-bold text-green-600">
                                {stats.totalRequests ? ((stats.successfulRequests / stats.totalRequests) * 100).toFixed(1) : 0}%
                            </p>
                        </div>
                        <TrendingUp className="h-8 w-8 text-green-600" />
                    </div>
                </div>

                <div className="card p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm text-gray-600">Failed Requests</p>
                            <p className="text-3xl font-bold text-red-600">{stats.failedRequests || 0}</p>
                        </div>
                        <AlertCircle className="h-8 w-8 text-red-600" />
                    </div>
                </div>

                <div className="card p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm text-gray-600">Active Users</p>
                            <p className="text-3xl font-bold text-purple-600">{stats.uniqueUsers || 0}</p>
                        </div>
                        <Users className="h-8 w-8 text-purple-600" />
                    </div>
                </div>

                <div className="card p-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm text-gray-600">Unique IPs</p>
                            <p className="text-3xl font-bold text-indigo-600">{stats.uniqueIPs || 0}</p>
                        </div>
                        <Globe className="h-8 w-8 text-indigo-600" />
                    </div>
                </div>
            </div>

           

          
            {/* Recent Activity Log */}
            <div className="card p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Chain of Custody Trail
                </h3>
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Status
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    User
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Endpoint
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Action
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    IP Address
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                    Timestamp
                                </th>
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                            {data.logs.slice(0, 20).map((log, index) => (
                                <tr key={index} className="hover:bg-gray-50">
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        {getStatusIcon(log.success)}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                        {log.name && log.surname ? `${log.name} ${log.surname}` : 'Unknown'}
                                        {log.email && (
                                            <div className="text-xs text-gray-500">{log.email}</div>
                                        )}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                        <code className="bg-gray-100 px-2 py-1 rounded text-xs">
                                            {log.endpoint}
                                        </code>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                        {log.action}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        {log.ip_address}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        {formatTimestamp(log.timestamp)}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {data.logs.length === 0 && (
                    <div className="text-center py-12">
                        <Clock className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                        <p className="text-gray-500">No activity logs found</p>
                    </div>
                )}
            </div>
        </div>
    )
}