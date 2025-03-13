from flask import Flask, render_template, jsonify, request, redirect, make_response, session
import requests
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
import jwt
from functools import wraps
from bson.objectid import ObjectId
from flask_cors import CORS
import threading

app = Flask(__name__)


client = MongoClient('localhost', 27017)
db = client.boards
users_collection = db.users
tokens_collection = db.tokens
CORS(app, supports_credentials=True)

scheduler = BackgroundScheduler(daemon=True)
scheduler.start()

@app.route("/api/check-login")
def check_login():
    token = request.cookies.get("access_token")  # 쿠키에서 JWT 토큰 가져오기
    if not token:
        return jsonify({"loggedIn": False})

    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # 토큰 검증
        return jsonify({"loggedIn": True})
    except jwt.ExpiredSignatureError:
        return jsonify({"loggedIn": False, "message": "토큰 만료"})
    except jwt.InvalidTokenError:
        return jsonify({"loggedIn": False, "message": "유효하지 않은 토큰"})





def decode_token():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None  # 유효하지 않은 토큰

    token = auth_header.split(" ")[1]  # "Bearer TOKEN"에서 TOKEN 추출
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # 토큰 검증 및 디코딩
        return payload.get("user_id")  # 토큰에서 userId 추출
    except jwt.ExpiredSignatureError:
        return None  # 토큰 만료
    except jwt.InvalidTokenError:
        return None  # 유효하지 않은 토큰

def decode_name():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None  # 유효하지 않은 토큰

    token = auth_header.split(" ")[1]  # "Bearer TOKEN"에서 TOKEN 추출
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # 토큰 검증 및 디코딩
        return payload.get("name")  # 토큰에서 name 추출
    except jwt.ExpiredSignatureError:
        return None  # 토큰 만료
    except jwt.InvalidTokenError:
        return None  # 유효하지 않은 토큰

def jwt_required(func):
    @wraps(func)
    def authenticated_function(*args, **kwargs):
        token = request.cookies.get("access_token")

        if not token:
            return jsonify({"error": "Authentication required"}), 401

        try:
            # JWT 토큰을 검증하고 해석
            jwt.decode(token, key=JWT_SECRET, algorithms=["HS256"])

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Access Token이 만료되었습니다."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Access Token 형식이 유효하지 않습니다."}), 401

        return func(*args, **kwargs)

    return authenticated_function


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/index.html', methods=['GET'])
def getMainPage():
    return render_template('index.html')

@app.route('/create-product.html', methods=['GET'])
def getCreateProduct():
    return render_template('create-product.html')

@app.route('/login.html')
def user_login():
    return render_template('login.html')

'''특정 게시물 페이지 '''
@app.route('/product-detail/<id>', methods=['GET'])
def product_detail(id):
    print('here', id)
    product = db.boards.find_one({"_id": ObjectId(id)})
    if product:
        return render_template('product-detail.html', product=product)
    else:
        return jsonify({"result": "fail", "message": "상품을 찾을 수 없습니다."}), 404

'''특정 상품 정보 조회'''
@app.route('/find_product/<id>', methods=["GET"])
def find_product(id):
        product_id = ObjectId(id)  # 유효한 ObjectId로 변환
        product = db.boards.find_one({"_id": product_id})

        product["_id"] = str(product["_id"])  # _id를 문자열로 변환하여 반환
        return jsonify({"result": "success", "product": product})


''' 모든 상품 게시글 조회'''
@app.route('/api/products', methods=['GET'])
def getAllProducts():
    check_ship_condition()
    result = list(db.boards.find({}))
    
    formatted_products = [
        {   
            "id": str(product["_id"]),
            "title": product["name"],  # 'name' 필드를 'title'로 변경
            "price": f"{product['price']}원",  # 가격에 "원" 추가
            "deadline": product["deadline"],  # 날짜 형식 그대로 사용
            "category": product["category"],
            "condition": product["condition"]
        }
        for product in result
    ]

    return jsonify({'result':'success', 'products': formatted_products})



'''상품 게시글 생성'''

@app.route('/api/product', methods=['POST'])
@jwt_required
def createProduct():
    userId = decode_token()
    print("!!!!!!here!!!!!!!", userId)
    if not userId:
       return jsonify({'error': 'Invalid or missing token'}), 401


    board = request.form['title']
    name = request.form['item_name']
    link = request.form['item_url']
    price = request.form['item_price']
    deadline = request.form['deadline'] # 2025-03-03, YYYY-MM-DD
    shipping = request.form['delivery_fee']
    condition = "N"
    #condition = request.form['free_delivery_cond']
    message = request.form['confirmation_msg']
    category = request.form['category']
    quantity = request.form['item_count']
    ownerId = userId

    product = { 'board': board, 'name':name, 'link':link, 'price':price, 
                'deadline':deadline, 'shipping':shipping, 'condition':condition, 
                'message':message, 'category':category, 'quantity':quantity, 
                'ownerId' : ownerId , 'participants': [], "expired": False}
    
    db.boards.insert_one(product)
    return jsonify({'result': 'success'})



def check_ship_condition():
    result = list(db.boards.find({}))

    for product in result:
        price = product['price']
        quantity = product['quantity']
        shipping = product['shipping']
        
        # price * quantity가 shipping보다 크면 condition을 "Y"로 업데이트
        if int(price) * int(quantity) >= int(shipping):
            db.boards.update_one(
                {'_id': product['_id']},
                {'$set': {'condition': 'Y'}}
            )
        else:
            # 기본값을 "N"으로 설정
            db.boards.update_one(
                {'_id': product['_id']},
                {'$set': {'condition': 'N'}})




'''마감일이 지난 상품 검색 -> 해당 메서드는 APScheduler를 통해 실행'''
def check_expired_products():
    """ 공동구매 마감된 게시글 찾고 상태 업데이트 """
    print("scheduling!")
    now = datetime.now().strftime("%Y-%m-%d")  # 날짜를 "YYYY-MM-DD" 형식의 문자열로 변환
    
    # # 마감 기한이 지난 게시글 조회
    # expired_products = db.boards.find({
    #     "deadline": {"$lt": now},  # 문자열 비교
    #     "expired": {"$ne": True}
    # })
    expired_products = db.boards.find({})
    print(expired_products)
    
    for product in expired_products:
        print("*")
        print(product)
        send_messageToparticipants(product)
        send_messageToOwner(product)
        db.boards.update_one(
            {"_id": product["_id"]},
            {"$set": {"expired": True}}
        )

''' 구매 희망 유저들에게 슬랙 디엠 전송 기능 '''
def send_messageToparticipants(product):
    message = product['message']
    participants = product['participants']

    for userId in participants:
        data = {
            'token' : slack_token,
            'channel' : userId,
            'as_user' : True,
            'text' : message
        }
        requests.post(
            url='https://slack.com/api/chat.postMessage',
            data=data)

''' 상품 게시글 게시자에게 슬랙 디엠 전송 기능 '''
def send_messageToOwner(product):
    total_quantity = product['quantity']
    total_price = int(product['price']) * int(product['quantity'])
    ownerId = product['ownerId']

    data = {
            'token' : slack_token,
            'channel' : ownerId,
            'as_user' : True,
            'text' : f"총 구매 금액은 {total_price}, 총 수량은 {total_quantity}"
    }
    
    requests.post(
            url='https://slack.com/api/chat.postMessage',
            data=data)


'''
OAuth 2.0 구현 
'''

@app.route('/oauth')
def oauth():
    slack_auth_url = (
        "https://slack.com/oauth/v2/authorize?"
        f"client_id={SLACK_CLIENT_ID}"
        "&scope=&user_scope=email,openid,profile"
        f"&redirect_uri={SLACK_REDIRECT_URI}"
        "&team=A08HEHGMUQL"
    )
    return redirect(slack_auth_url)


@app.route('/oauth/callback')
def oauth_callback(provider="slack"):
    # 유저가 전달한 authorization_code 수신
    code = request.args.get("code")
    if not code:
        return "Authorization failed", 400

    # Slack OAuth 서버에 Access Token 요청
    token_response = requests.post(
        "https://slack.com/api/oauth.v2.access",
        data = {
            "client_id": SLACK_CLIENT_ID,
            "client_secret": SLACK_CLIENT_SECRET,
            "code": code,
            "redirect_uri": SLACK_REDIRECT_URI,
        }
    )

    token_data = token_response.json()
    if not token_data.get("ok"):
        return "OAuth 실패", 400
    
    access_token = token_data["authed_user"]["access_token"]

    # Access Token을 통해 유저 정보 가져오기
    user_info_response = requests.get(
        "https://slack.com/api/openid.connect.userInfo",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    user_info = user_info_response.json()
    if not user_info.get("ok"):
        return "알 수 없는 유저입니다.", 400

    user = {"id": user_info.get("sub"),
            "name": user_info.get("name"), 
            "email": user_info.get("email")}
    
    # JWT token 발급
    access_token = generate_token(user, ACCESS_TOKEN_EXPIRY_DAYS)
    refresh_token = generate_token(user, REFRESH_TOKEN_EXPIRY_DAYS)

    # DB에 사용자 저장 
    users_collection.update_one(
        user,
        {"$set": {"token": refresh_token}},
        upsert=True
    )

    # 쿠키에 Access Token 저장 후 메인 페이지로 리디렉트
    response = make_response(redirect(MAIN_URL+"/index.html"))
    response.set_cookie("access_token", access_token, httponly=False, secure=True, samesite="Lax", max_age=ACCESS_TOKEN_EXPIRY_DAYS * 86400)  

    return response # 기본 엔그록 url + index.html

def generate_token(user, token_expiry_days):
    payload = {
        "user_id": user.get("id"),
        "name": user.get("name"),
        "email": user.get("email"),
        "exp": (datetime.now(timezone.utc) + timedelta(days=token_expiry_days)).timestamp(),
    }

    return jwt.encode(payload=payload, key=JWT_SECRET, algorithm=JWT_ALGORITHM)





''' 
댓글 대댓글 기능 구현
''' 

@app.route('/new_comment', methods=['POST']) #id는 자동생성되는 친구 쓰는거로~
@jwt_required
def new_comment():
    user_name = decode_name()
    print(request.form['post_id'])
    post_id = ObjectId(request.form['post_id'])  # 댓글을 추가할 게시글 ID
    #comment_author = 댓글 작성장의 슬렉 계정정
    text = request.form['text']

    comment = {
        "_id" : str(datetime.now(timezone.utc).timestamp()*1000),
        #'comment_author_id": comment_author,
        "participantId" : user_name,
        "text": text,
        "created_at": datetime.now(timezone.utc),
        "updated_at": 0,
        "status" : 'valid',
        "replies": [],  # 대댓글 
        
    }

    # 게시글 컬렉션에 저장
    result = db.boards.update_one(
        {"_id": post_id},
        {"$push": {"comments": comment}}
    )

    # 시연용 스케쥴러
    run_time = datetime.now() + timedelta(seconds=10)
    scheduler.add_job(check_expired_products, 'date', run_date=run_time)

    if result.modified_count > 0:
        return jsonify({"result": "success", "message": "댓글이 추가되었습니다."})
    else:
        return jsonify({"result": "fail", "message": "게시글을 찾을 수 없습니다."})
    
@app.route('/read_comment/<id>', methods=["GET"])
def read_comment(id):
        product_id = ObjectId(id)  # 유효한 ObjectId로 변환
        products = db.boards.find_one({"_id": product_id})
        comments = products["comments"]
        for i in range(len(products["comments"])):
            comments[i]["_id"] = str(comments[i]["_id"])  # _id를 문자열로 변환하여 반환
        return jsonify({"result": "success", "response": comments})

@app.route('/update_comment', methods=['POST']) 
def Update_comment():
    comment_id = request.form['comment_id']  
    text = request.form['update_text']

    result = db.boards.update_one(
        {"comments._id": comment_id},
        {"$set": {"comments.$.text": text, "comments.$.updated_at": datetime.now(timezone.utc)}}
    )



    if result.modified_count > 0:
        return jsonify({"result": "success", "message": "댓글이 수정되었습니다."})

@app.route('/delete_comment', methods=['POST']) 
def delete_comment():
    comment_id = request.form['comment_id']  
    result = db.boards.update_one(
        {"comments._id": comment_id },
        {"$set": {"comments.$.status": "deleted" }}
    )

    if result.modified_count > 0:
        return jsonify({"result": "success", "message": "댓글이 삭제되었습니다."})

''' 대댓글 생성 ''' 
@app.route('/new_reply', methods=['POST'])
def New_reply():
    user_name = decode_name()
    print("1", user_name)
    post_id = ObjectId(request.form['post_id'])  # 게시글 ID
    comment_id = request.form['comment_id']  # 부모 댓글 ID
    # reply_author = 슬렉 계정 사용자
    text = request.form['text']

    new_reply = {
        "_id" : str(datetime.now(timezone.utc).timestamp()*1000),
        #"author_id": reply_author,
        "text": text,
        "created_at": datetime.now(timezone.utc),
        "updated_at" : 0,
        "status" : 'valid',
        "user_name" : user_name
    }

    result = db.boards.update_one(
        {"_id": post_id, "comments._id": comment_id},
        {"$push": { "comments.$.replies" : new_reply}}
    )

    if result.modified_count > 0:
        return jsonify({"result": "success", "message": "대댓글이 추가되었습니다."})
    else:
        return jsonify({"result": "fail", "message": "댓글을 찾을 수 없습니다."})
    
@app.route('/read_replies/<id>', methods=["GET"])
def read_replies(id):
        product_id = ObjectId(id)  # 유효한 ObjectId로 변환
        comment_id = request.form['comment_id']  # 부모 댓글 ID
        comments = db.boards.find_one({"_id" : product_id, "comments._id": comment_id})
        replies = comments["replies"]
        print("2", comments["replies"][0]["user_name"])
        return jsonify({"result": "success", "response": replies})

@app.route('/update_reply', methods=['POST'])
def Update_reply():
    post_id = ObjectId(request.form['post_id'])  # 게시글 ID
    comment_id = request.form['comment_id']  # 부모 댓글 ID
    reply_id = request.form['reply_id'] #대댓글 ID
    # reply_author = 슬렉 계정 사용자
    text = request.form['text'] # 수정된 대댓글글

    result = db.boards.update_one(
        {"_id" : post_id, "comments._id": comment_id, "comments.replies._id" : reply_id},
        {"$set": {
            "comments.$.replies.$[elem].text": text,
            "comments.$.replies.$[elem].updated_at": datetime.now(timezone.utc)
        }},
        array_filters=[{"elem._id": reply_id}]  
    )

    if result.modified_count > 0:
        return jsonify({"result": "success", "message": "대댓글이 수정정되었습니다."})
    
@app.route('/delete_reply', methods=['POST'])
def delete_reply():
    post_id = ObjectId(request.form['post_id'])
    comment_id = request.form['comment_id']
    reply_id = request.form['reply_id']

    result = db.boards.update_one(
        {"_id": post_id, "comments._id": comment_id, "comments.replies._id": reply_id},
        {"$set": {"comments.$.replies.$[elem].status": "deleted"}},
        array_filters=[{"elem._id": reply_id}]
    )

    if result.modified_count > 0:
        return jsonify({"result": "success", "message": "대댓글이 삭제되었습니다."})
    else:
        return jsonify({"result": "fail", "message": "대댓글을 찾을 수 없습니다."})

# ''' 모달창 기능'''
# @app.route('/buy_product/<id>', methods=['POST'])
# def buy_porduct(id):

#     user_id = decode_token()  # 토큰에서 user_id 가져오기
#     if not user_id:
#         return jsonify({"result": "fail", "message": "인증되지 않은 사용자입니다."}), 401


#     post_id = ObjectId(request.form['post_id'])
#     amount = int(db.boards.find_one({'_id' : post_id})['quantity'])
#     buy_amount = int(request.form['purchase_amount'])
#     update_amount = amount + buy_amount


#     participants = product.get("participants", [])
#     if user_id not in participants:
#         participants.append(user_id)  # user_id 추가


#     result = db.boards.update_one(
#         {'_id': post_id},
#         {"$set": {"quantity": update_amount, "participants": participants}}
#     )

#     if result.modified_count > 0:
#         return jsonify({"result": "success", "message": "구매에 참여했습니다!!!"})
#     else:
#         return jsonify({"result": "fail", "message": "오류 발생으로 재시도 바랍니다."})

@app.route('/buy_product/<id>', methods=['POST'])
def buy_product(id):
    user_id = decode_token()  # 토큰에서 user_id 가져오기
    if not user_id:
        return jsonify({"result": "fail", "message": "인증되지 않은 사용자입니다."}), 401

    post_id = ObjectId(request.form['post_id'])
    
    # 현재 상품 정보 조회
    product = db.boards.find_one({'_id': post_id})
    if not product:
        return jsonify({"result": "fail", "message": "상품을 찾을 수 없습니다."}), 404

    # 구매 수량 업데이트
    amount = int(product['quantity'])
    buy_amount = int(request.form['purchase_amount'])
    update_amount = amount + buy_amount

    # 기존 participants 리스트 가져오기
    participants = product.get("participants", [])
    owner_id = product.get("ownerId")
    if user_id != owner_id and user_id not in participants:
        participants.append(user_id)    # user_id 추가

    # DB 업데이트
    result = db.boards.update_one(
        {'_id': post_id},
        {"$set": {"quantity": update_amount, "participants": participants}}
    )

    if result.modified_count > 0:
        return jsonify({"result": "success", "message": "구매에 참여했습니다!!!"})
    else:
        return jsonify({"result": "fail", "message": "오류 발생으로 재시도 바랍니다."})

if __name__ == '__main__':
    app.run('0.0.0.0', port=5001, debug=True)
    

