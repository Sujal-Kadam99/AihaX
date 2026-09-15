from flask import Flask, request, jsonify
import time

app = Flask(__name__)

# Mock Database
users = {"1": {"name": "Alice", "role": "user"}}
prices = {"item_1": 10.0}
coupons = {"DISCOUNT10": 1} # Only 1 usage allowed

@app.route('/api/user/1', methods=['POST'])
def update_user():
    data = request.json or {}
    # C070 Mass Assignment vulnerability: blindly accepts all keys including 'role'
    for k, v in data.items():
        users["1"][k] = v
    return jsonify(users["1"])

@app.route('/api/buy', methods=['GET'])
def buy_item():
    # C073 Parameter Tampering vulnerability: trusts client price
    price = request.args.get('price', type=float)
    if price is None:
        price = prices.get("item_1")
    
    # In a real app this would deduct balance, here we just return success
    return jsonify({"status": "success", "charged": price})

@app.route('/api/redeem', methods=['POST'])
def redeem_coupon():
    # C075 Race Condition vulnerability: check-then-act without locking
    data = request.json or {}
    coupon = data.get("coupon", "DISCOUNT10")
    
    if coupons.get(coupon, 0) > 0:
        # Simulate delay to increase race window
        time.sleep(0.1)
        coupons[coupon] -= 1
        return jsonify({"status": "success", "message": "Coupon redeemed"})
    else:
        return jsonify({"status": "error", "message": "Coupon exhausted"}), 400

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5006, debug=False, use_reloader=False)
