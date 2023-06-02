import hashlib
import logging
import json
import os
from datetime import datetime

import jwt
import redis
from flask import Flask, request, jsonify

from bignum import PrimeGenerator

# 将类变量从config.json中读取
config_file = os.path.join(os.path.dirname(__file__), 'config.json')
config = json.load(open(config_file, 'r'))


class PoWServer:
    def __init__(self):
        # 连接到 Redis
        self.redis = redis.Redis(host=config['redis_host'], port=config['redis_port'], db=config['redis_db'],
                                 password=config['redis_password'])
        self.secret_key = config['secret_key']
        self.salt = config['salt']
        self.redis_exp_sec = config['redis_exp_sec']
        self.token_exp_sec = config['token_exp_sec']
        self.bits = config['bits']
        self.app = Flask(__name__)
        self.route()
        # 设置logging级别
        if 'GUNICORN_CMD_ARGS' in os.environ:
            gunicorn_logger = logging.getLogger('gunicorn.error')
            self.app.logger.handlers = gunicorn_logger.handlers
            self.app.logger.setLevel(gunicorn_logger.level)
        else:
            logging.basicConfig(level=getattr(logging, config['logging_level'].upper(), logging.INFO),
                                format='%(asctime)s - %(levelname)s - %(message)s')

    def request_token(self):
        prime_generator = PrimeGenerator(self.bits)
        challenge, p1, p2, _ = prime_generator.generate_large_number()
        # log打印challenge p1 p2 ElapsedTime的值
        logging.info(f"challenge: {challenge}, p1: {p1}, p2: {p2}, ElapsedTime: {_}")
        current_timestamp = int((datetime.utcnow().timestamp()) * 1000_000)
        # 当header中没有UA时，返回401
        if not request.headers.get('User-Agent'):
            return jsonify({'error': 'No User-Agent'}), 401
        raw_data = request.remote_addr + request.headers.get('User-Agent') \
                   + str(current_timestamp) + self.salt
        request_id = hashlib.sha256(raw_data.encode()).hexdigest()
        self.redis.set(name=request_id, ex=self.redis_exp_sec, value=f"{p1},{p2}")  # 将问题及其答案存储到 Redis
        logging.info(f"func request_token request_id: {request_id}, challenge: {challenge}, p1: {p1}, p2: {p2}")
        return jsonify(
            {
                'challenge': {
                    'request_id': request_id,
                    'challenge': str(challenge)
                },
                'request_time': current_timestamp,
            }
        ), 200

    def submit(self):
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        try:
            request_id = data['challenge']['request_id']
            submitted_answer = data['answer']
            request_time = data['request_time']
        except KeyError:
            return jsonify({'error': 'Invalid data format'}), 400
        raw_data = request.remote_addr + request.headers.get('User-Agent') \
                   + str(request_time) + self.salt
        correct_answer = self.redis.get(request_id)
        if correct_answer:
            correct_answer = correct_answer.decode().split(',')
            # log打印correct_answer 和 submitted_answer 的值
            logging.info(f"correct_answer: {correct_answer}, submitted_answer: {submitted_answer}")
            if sorted(submitted_answer) == sorted(correct_answer):
                # 验证ip,ua,request_time是否对应此request_id
                if hashlib.sha256(raw_data.encode()).hexdigest() != request_id:
                    return jsonify({'error': 'Wrong request_id'}), 400
                x_forwarded_for = request.headers.get('x-forwarded-for')
                if x_forwarded_for:
                    ip = x_forwarded_for.split(',')[0].strip()
                else:
                    ip = request.remote_addr
                logging.info(f"ip: {ip}, ua: {request.headers.get('User-Agent')}")
                logging.info(f"ip.hash: {hashlib.sha256((ip + self.salt).encode()).hexdigest()}")
                logging.info(
                    f"ua.hash: {hashlib.sha256((request.headers.get('User-Agent') + self.salt).encode()).hexdigest()}")
                payload = {
                    'exp': int((datetime.utcnow().timestamp() + self.token_exp_sec) * 1000_000),
                    'ip': hashlib.sha256((ip + self.salt).encode()).hexdigest(),
                    'ua': hashlib.sha256((request.headers.get('User-Agent') + self.salt).encode()).hexdigest(),
                }
                token = jwt.encode(
                    payload,
                    self.secret_key,
                    algorithm="HS256"
                )
                self.redis.delete(request_id)  # 删除已解答的问题
                logging.info(f"func submit token: {token}")
                return jsonify(
                    {
                        'token': token,
                    }
                ), 200
            else:
                return jsonify({'error': 'Wrong answer'}), 400
        else:
            # 问题不存在或已过期
            return jsonify({'error': 'Challenge does not exist or has expired'}), 400

    def verify_request(self):
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        try:
            token = data['token']
            ip = data['ip']
            ua = data['ua']
            logging.info(f"func verify_request token: {token}, ip: {ip}, ua: {ua}")
        except KeyError:
            return jsonify({'error': 'Invalid data format'}), 400
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        try:
            decoded = jwt.decode(token, self.secret_key, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        current_timestamp = int((datetime.utcnow().timestamp()) * 1000_000)
        if decoded.get('exp', 0) < current_timestamp:
            return jsonify({'error': 'Token has expired'}), 401
        if decoded.get('ip') != hashlib.sha256((ip + self.salt).encode()).hexdigest():
            return jsonify({'error': 'Invalid ip'}), 401
        if decoded.get('ua') != hashlib.sha256((ua + self.salt).encode()).hexdigest():
            return jsonify({'error': 'Invalid ua'}), 401
        return jsonify({'message': 'Token is valid'}), 200

    def route(self):
        self.app.route('/request_challenge', methods=['GET'])(self.request_token)
        self.app.route('/submit_answer', methods=['POST'])(self.submit)
        self.app.route('/verify_token', methods=['POST'])(self.verify_request)

    def run(self, host='0.0.0.0', port=55000):
        self.app.run(host=host, port=port)


# 在这里创建PoWServer实例
server = PoWServer()
APP = server.app
if __name__ == '__main__':
    server.run()
