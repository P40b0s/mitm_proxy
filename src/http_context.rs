use hyper::{Request, HeaderMap};
use hyper::header::{HeaderName, CONTENT_TYPE, ETAG, LAST_MODIFIED, RANGE, ACCEPT, ACCEPT_LANGUAGE, USER_AGENT, AUTHORIZATION, CONTENT_RANGE};
use std::hash::{Hash, Hasher, DefaultHasher};
use std::net::SocketAddr;

/// Context for HTTP requests and responses.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct HttpContext {
    /// Address of the client that is sending the request.
    pub client_addr: SocketAddr,
    pub request_method: hyper::Method,
    pub request_uri: hyper::Uri,
    pub content_type: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub byte_range: Option<String>,
    pub accept: Option<String>,
    pub accept_language: Option<String>,
    pub user_agent: Option<String>,
    pub authorization_hash: Option<String>,
    pub content_range: Option<String>, // Для ответов с частичным контентом
}


impl HttpContext {
    pub fn from_request<B: hyper::body::Body>(req: &Request<B>, client_addr: std::net::SocketAddr) -> Self {
        let headers = req.headers();
        
        // Базовые заголовки
        let content_type = Self::get_header_string(headers, &CONTENT_TYPE);
        let etag = Self::get_header_string(headers, &ETAG);
        let last_modified = Self::get_header_string(headers, &LAST_MODIFIED);
        let byte_range = Self::get_header_string(headers, &RANGE);
        let accept = Self::get_header_string(headers, &ACCEPT);
        let accept_language = Self::get_header_string(headers, &ACCEPT_LANGUAGE);
        let user_agent = Self::get_header_string(headers, &USER_AGENT);
        let content_range = Self::get_header_string(headers, &CONTENT_RANGE);
        
        // Авторизация (хешируем для безопасности)
        let authorization_hash = Self::get_header_string(headers, &AUTHORIZATION)
            .map(|auth| Self::short_hash(&auth, 8));
        
        HttpContext {
            client_addr,
            request_method: req.method().clone(),
            request_uri: req.uri().clone(),
            content_type,
            etag,
            last_modified,
            byte_range,
            accept,
            accept_language,
            user_agent,
            authorization_hash,
            content_range,
        }
    }
    
    // Универсальный метод генерации ключа для любого типа контента
    pub fn generate_cache_key(&self) -> String {
        let mut composite = String::new();
        
        // 1. Базовый компонент: хеш URI + метод
        let mut hasher = DefaultHasher::new();
        self.request_uri.hash(&mut hasher);
        self.request_method.hash(&mut hasher);
        let base_hash = format!("{:x}", hasher.finish());
        composite.push_str(&base_hash[..12]); // Берем первые 12 символов
        
        // 2. Анализируем URI для определения типа контента
        let content_info = self.analyze_content_type();
        
        // 3. Добавляем информацию о типе контента
        composite.push_str("_t:");
        composite.push_str(&content_info.content_type_code);
        
        // 4. Для медиа/стриминга добавляем специфичные параметры
        if content_info.is_media {
            composite.push_str("_m");
            
            // Разрешение/качество из пути или параметров
            if let Some(res) = content_info.resolution {
                composite.push_str("_r:");
                composite.push_str(&res);
            }
            
            // Битрейт
            if let Some(br) = content_info.bitrate {
                composite.push_str("_br:");
                composite.push_str(&br);
            }
            
            // Кодек
            if let Some(codec) = content_info.codec {
                composite.push_str("_c:");
                composite.push_str(&codec);
            }
        }
        
        // 5. Для стриминга добавляем информацию о сегменте
        if content_info.is_streaming {
            composite.push_str("_s");
            
            // Индекс сегмента
            if let Some(seg_idx) = content_info.segment_index {
                composite.push_str(&format!("_seg{}", seg_idx));
            }
            
            // Инициализационный сегмент
            if content_info.is_init_segment {
                composite.push_str("_init");
            }
            
            // Playlist ID
            if let Some(playlist_id) = content_info.playlist_id {
                composite.push_str("_pl:");
                composite.push_str(&Self::short_hash(&playlist_id, 6));
            }
        }
        
        // 6. Диапазон байтов (важно для частичных загрузок и стриминга)
        if let Some(range) = self.byte_range.as_ref().or(self.content_range.as_ref()) {
            composite.push_str("_range:");
            let clean_range = Self::normalize_range(range);
            composite.push_str(&Self::short_hash(&clean_range, 8));
        }
        
        // 7. Тип контента из заголовка
        if let Some(ct) = &self.content_type {
            composite.push_str("_cth:");
            composite.push_str(&Self::short_hash(ct, 6));
        }
        
        // 8. ETag (сильный валидатор)
        if let Some(etag) = &self.etag {
            composite.push_str("_et:");
            // Удаляем кавычки и хешируем
            let clean_etag = etag.trim_matches('"');
            composite.push_str(&Self::short_hash(clean_etag, 8));
        }
        
        // 9. Accept заголовок (content negotiation)
        if let Some(accept) = &self.accept {
            composite.push_str("_acc:");
            // Берем первый тип из списка Accept
            let first_accept = accept.split(',').next().unwrap_or("");
            composite.push_str(&Self::short_hash(first_accept, 4));
        }
        
        // 10. Язык
        if let Some(lang) = &self.accept_language {
            composite.push_str("_lang:");
            let first_lang = lang.split(',').next().unwrap_or("");
            composite.push_str(&Self::short_hash(first_lang, 3));
        }
        
        // 11. User-Agent (сокращенный хеш)
        if let Some(ua) = &self.user_agent {
            composite.push_str("_ua:");
            composite.push_str(&Self::short_hash(ua, 6));
        }
        
        // 12. Авторизация (если контент приватный)
        if let Some(auth) = &self.authorization_hash {
            composite.push_str("_auth:");
            composite.push_str(auth);
        }
        
        // 13. Last-Modified (слабая валидация)
        if let Some(lm) = &self.last_modified {
            composite.push_str("_lm:");
            composite.push_str(&Self::short_hash(lm, 8));
        }
        
        // 14. Хеш query параметров (если есть)
        if let Some(query) = self.request_uri.query() {
            if !query.is_empty() {
                composite.push_str("_q:");
                composite.push_str(&Self::short_hash(query, 8));
            }
        }
        
        composite
    }
    
    // Анализ URI для определения типа контента
    fn analyze_content_type(&self) -> ContentInfo {
        let path = self.request_uri.path().to_lowercase();
        let query = self.request_uri.query().unwrap_or("");
        
        let mut info = ContentInfo::default();
        
        // Определяем расширение файла
        let extension = path.split('.').last().unwrap_or("");
        
        // Код типа контента
        info.content_type_code = match extension {
            "mp4" | "avi" | "mov" | "mkv" | "webm" => {
                info.is_media = true;
                "vid".to_string()
            }
            "mp3" | "wav" | "ogg" | "flac" | "aac" => {
                info.is_media = true;
                "aud".to_string()
            }
            "m3u8" | "mpd" => {
                info.is_media = true;
                info.is_streaming = true;
                "str".to_string()
            }
            "ts" | "m4s" | "chk" => {
                info.is_media = true;
                info.is_streaming = true;
                // Извлекаем номер сегмента
                info.segment_index = extract_segment_number(&path);
                "seg".to_string()
            }
            "jpg" | "jpeg" | "png" | "gif" | "webp" => "img".to_string(),
            "pdf" | "doc" | "docx" | "xls" | "xlsx" => "doc".to_string(),
            "js" => "js".to_string(),
            "css" => "css".to_string(),
            "html" | "htm" => "html".to_string(),
            "json" | "xml" => "data".to_string(),
            _ => {
                // Проверяем по пути
                if path.contains("/video/") || path.contains("/media/") {
                    info.is_media = true;
                    "vid".to_string()
                } else if path.contains("/audio/") {
                    info.is_media = true;
                    "aud".to_string()
                } else if path.contains("/stream/") || path.contains("/hls/") || path.contains("/dash/") {
                    info.is_media = true;
                    info.is_streaming = true;
                    "str".to_string()
                } else if path.contains("/segment") || path.contains("/chunk") {
                    info.is_media = true;
                    info.is_streaming = true;
                    info.segment_index = extract_segment_number(&path);
                    "seg".to_string()
                } else if path.contains("/init") || query.contains("init=1") {
                    info.is_media = true;
                    info.is_streaming = true;
                    info.is_init_segment = true;
                    "init".to_string()
                } else {
                    "gen".to_string() // generic
                }
            }
        };
        
        // Извлекаем параметры качества из query строки
        if info.is_media {
            info.resolution = extract_query_param(query, "resolution")
                .or_else(|| extract_query_param(query, "res"))
                .or_else(|| extract_query_param(query, "quality"))
                .or_else(|| extract_query_param(query, "q"));
                
            info.bitrate = extract_query_param(query, "bitrate")
                .or_else(|| extract_query_param(query, "br"));
                
            info.codec = extract_query_param(query, "codec")
                .or_else(|| extract_query_param(query, "c"));
                
            info.playlist_id = extract_query_param(query, "playlist")
                .or_else(|| extract_query_param(query, "pl"));
        }
        
        // Также проверяем путь на наличие параметров качества
        if info.resolution.is_none() {
            if let Some(res) = extract_resolution_from_path(&path) {
                info.resolution = Some(res);
            }
        }
        
        info
    }
    
    // Вспомогательные методы
    fn get_header_string(headers: &HeaderMap, header_name: &HeaderName) -> Option<String> {
        headers.get(header_name)
            .and_then(|value| value.to_str().ok())
            .map(|s| s.to_string())
    }
    
    fn short_hash(s: &str, length: usize) -> String {
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        let hash = format!("{:x}", hasher.finish());
        hash[..std::cmp::min(length, hash.len())].to_string()
    }
    
    fn normalize_range(range: &str) -> String {
        range
            .to_lowercase()
            .replace("bytes=", "")
            .replace(" ", "")
            .replace("-", "_")
    }
}

// Структура для информации о контенте
#[derive(Debug, Default, Clone)]
struct ContentInfo {
    content_type_code: String,
    is_media: bool,
    is_streaming: bool,
    segment_index: Option<u32>,
    is_init_segment: bool,
    resolution: Option<String>,
    bitrate: Option<String>,
    codec: Option<String>,
    playlist_id: Option<String>,
}

// Вспомогательные функции для анализа пути и query
fn extract_segment_number(path: &str) -> Option<u32> {
    // Ищем паттерны: segment_123, chunk456, /123.ts, segment=123
    let patterns = [
        (r"segment[_-]?(\d+)", 1),
        (r"chunk[_-]?(\d+)", 1),
        (r"/(\d+)\.(ts|m4s|chk)", 1),
        (r"seg[_-]?(\d+)", 1),
        (r"(\d+)_\d+\.ts", 1), // Для HLS: 123_456.ts
    ];
    
    for (pattern, group) in &patterns {
        if let Some(captures) = regex::Regex::new(pattern).ok()
            .and_then(|re| re.captures(path)) 
        {
            if let Some(matched) = captures.get(*group) {
                if let Ok(num) = matched.as_str().parse::<u32>() {
                    return Some(num);
                }
            }
        }
    }
    
    None
}

fn extract_resolution_from_path(path: &str) -> Option<String> {
    // Ищем паттерны: 1080p, 720p, 1920x1080, etc.
    let patterns = [
        r"(\d{3,4}[px])", // 1080p, 720p
        r"(\d{3,4}x\d{3,4})", // 1920x1080
        r"(hd|sd|fullhd|4k|8k)", // качественные обозначения
    ];
    
    for pattern in &patterns {
        if let Some(captures) = regex::Regex::new(pattern).ok()
            .and_then(|re| re.captures(path))
        {
            if let Some(matched) = captures.get(1) {
                return Some(matched.as_str().to_string());
            }
        }
    }
    
    None
}

fn extract_query_param(query: &str, param_name: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut parts = pair.split('=');
        if let Some(key) = parts.next() {
            if key == param_name {
                return parts.next().map(|s| s.to_string());
            }
        }
    }
    None
}