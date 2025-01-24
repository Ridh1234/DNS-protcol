from flask import Flask, render_template, request, jsonify
from advanced_dns_resolver import AdvancedDNSResolver

app = Flask(__name__)
resolver = AdvancedDNSResolver()

@app.route('/')
def index():
    return render_template('advanced_index.html')

@app.route('/resolve', methods=['POST'])
def resolve_domain():
    domain = request.form.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        # Comprehensive resolution
        dns_result = resolver.resolve_dns(domain)
        whois_result = resolver.get_whois_info(domain)
        
        # Get network info for first IP
        network_info = {}
        ssl_info = {}
        if dns_result.get('ipv4'):
            network_info = resolver.network_info(dns_result['ipv4'][0])
        
        try:
            ssl_info = resolver.check_ssl(domain)
        except Exception:
            ssl_info = {'error': 'SSL check failed'}
        
        return jsonify({
            'dns': dns_result,
            'whois': whois_result,
            'network': network_info,
            'ssl': ssl_info
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)