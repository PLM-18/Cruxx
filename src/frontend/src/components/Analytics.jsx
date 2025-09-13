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

            {/* Anomalies Alert */}
            {data.anomalies.length > 0 && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-6">
                    <div className="flex items-start">
                        <AlertTriangle className="h-6 w-6 text-red-600 mr-3 mt-1" />
                        <div className="flex-1">
                            <h3 className="text-lg font-medium text-red-900 mb-2">
                                Security Anomalies Detected ({data.anomalies.length})
                            </h3>
                            <div className="space-y-2">
                                {data.anomalies.slice(0, 3).map((anomaly, index) => (
                                    <div key={index} className="flex items-center justify-between bg-white rounded p-3">
                                        <div>
                                            <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(anomaly.severity)} mr-3`}>
                                                {anomaly.severity}
                                            </span>
                                            <span className="text-sm font-medium text-gray-900">{anomaly.type}</span>
                                            <p className="text-sm text-gray-600 mt-1">{anomaly.description}</p>
                                        </div>
                                        <span className="text-xs text-gray-500">
                                            {formatTimestamp(anomaly.timestamp)}
                                        </span>
                                    </div>
                                ))}
                                {data.anomalies.length > 3 && (
                                    <p className="text-sm text-red-700">
                                        +{data.anomalies.length - 3} more anomalies detected
                                    </p>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Charts Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Hourly Activity Chart */}
                <div className="card p-6">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">
                        Hourly Activity Pattern
                    </h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <LineChart data={hourlyData}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="hour" />
                            <YAxis />
                            <Tooltip />
                            <Legend />
                            <Line
                                type="monotone"
                                dataKey="requests"
                                stroke="#3b82f6"
                                strokeWidth={2}
                                dot={{ fill: '#3b82f6' }}
                            />
                        </LineChart>
                    </ResponsiveContainer>
                </div>

                {/* Endpoint Performance */}
                <div className="card p-6">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">
                        Endpoint Performance
                    </h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <BarChart data={endpointData}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="endpoint" />
                            <YAxis />
                            <Tooltip />
                            <Legend />
                            <Bar dataKey="success" stackId="a" fill="#10b981" name="Success" />
                            <Bar dataKey="failed" stackId="a" fill="#ef4444" name="Failed" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Anomaly Distribution */}
            {anomalyData.some(d => d.count > 0) && (
                <div className="card p-6">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">
                        Anomaly Distribution by Severity
                    </h3>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <ResponsiveContainer width="100%" height={300}>
                            <PieChart>
                                <Pie
                                    data={anomalyData.filter(d => d.count > 0)}
                                    cx="50%"
                                    cy="50%"
                                    labelLine={false}
                                    label={({ severity, count }) => `${severity}: ${count}`}
                                    outerRadius={80}
                                    fill="#8884d8"
                                    dataKey="count"
                                >
                                    {anomalyData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip />
                            </PieChart>
                        </ResponsiveContainer>

                        <div className="space-y-4">
                            {anomalyData.filter(d => d.count > 0).map((item) => (
                                <div key={item.severity} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                    <div className="flex items-center">
                                        <div
                                            className="w-4 h-4 rounded-full mr-3"
                                            style={{ backgroundColor: item.color }}
                                        />
                                        <span className="font-medium text-gray-900">{item.severity} Severity</span>
                                    </div>
                                    <span className="text-2xl font-bold text-gray-700">{item.count}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {/* Recent Activity Log */}
            <div className="card p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Recent Activity Log
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