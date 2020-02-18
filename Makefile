build:
	docker build -t flask-url-shortener:latest .

run: 
	docker run -p 5000:5000 flask-url-shortener
