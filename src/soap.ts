import axios from 'axios';
import https from 'node:https';
// 2. 配置 Axios 实例（处理自签名证书）
const axiosInstance = axios.create({
    httpsAgent: new https.Agent({
        rejectUnauthorized: false // 允许自签名证书
    })
});
export async function sendArtifactResolve(url:string,soapRequest:any) {
    try {
        const response = await axiosInstance.post(
            url,
            soapRequest,
            {
                headers: {
                    'Content-Type': 'application/soap+xml; charset=utf-8',
                    'SOAPAction': '"ArtifactResolve"'
                },
                timeout: 5000 // 5秒超时
            }
        );

        console.log('✅ Resolve请求成功')
        return response.data;
    } catch (error) {
        console.error('❌ Resolve请求失败');
        throw error.response.data;
    }
}