# PhishR -  Malware Detection Integrating Hybrid Machine Learning Model
This is a for malware detection web-based system integrating hybrid machine learning models. 

## Details
Frontend Architecture: 
The user interface is built using modern web technologies including HTML5, CSS3, and JavaScript. The interface provides responsive design elements that function across desktop and mobile platforms.

Backend Infrastructure: The server-side architecture utilizes Python with the FastAPI framework to provide high-performance API endpoints. The system employs asynchronous processing to handle multiple concurrent scanning requests efficiently.

Machine Learning Pipeline: The detection engine incorporates multiple algorithms including XGBoost, Random Forest, Gradient Boosting​ in an ensemble configuration. The pipeline includes feature extraction (with BeautifulSoap), preprocessing, and prediction components.

Database Design: MongoDB is used for data persistence, storing user information, scan histories, and system configurations. The database design supports horizontal scaling and efficient querying for large datasets.

Authentication and Security: The system implements JSON Web Token based authentication with role-based access controls. Administrative functions are protected with additional security layers.

API Design: RESTful API endpoints provide programmatic access to scanning functions, supporting both single URL analysis and bulk processing operations.

Real-time Processing: The system supports real-time URL analysis with response times typically under 5 seconds for single URLs and scalable processing for bulk operations.

This is the Swinburne university projects.



