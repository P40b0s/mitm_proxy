use hyper::{Request, HeaderMap};
use hyper::header::{HeaderName, CONTENT_TYPE, ETAG, LAST_MODIFIED, RANGE, ACCEPT, ACCEPT_LANGUAGE, USER_AGENT, AUTHORIZATION, CONTENT_RANGE, HOST};
use std::net::SocketAddr;
use std::collections::HashMap;

/// Comprehensive HTTP request information for cache analysis and decision making.
#[derive(Clone, Debug)]
pub struct HttpContext {
    /// Client address
    pub client_addr: SocketAddr,
    
    /// HTTP method
    pub request_method: hyper::Method,
    
    /// Request URI
    pub request_uri: hyper::Uri,
    
    /// Full path
    pub path: String,
    
    /// Query parameters as key-value pairs
    pub query_params: HashMap<String, String>,
    
    /// Headers
    pub headers: RequestHeaders,
    
    /// Content analysis
    pub content_info: ContentInfo,
    
    /// Authentication info (hashed for security)
    pub auth_info: Option<AuthInfo>,
    
    /// Network and connection info
    pub network_info: NetworkInfo,
}

/// HTTP headers information
#[derive(Clone, Debug)]
pub struct RequestHeaders {
    pub content_type: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub byte_range: Option<String>,
    pub accept: Option<String>,
    pub accept_language: Option<String>,
    pub user_agent: Option<String>,
    pub authorization: Option<String>,
    pub content_range: Option<String>,
    pub host: Option<String>,
    pub referer: Option<String>,
    pub cache_control: Option<String>,
    pub if_none_match: Option<String>,
    pub if_modified_since: Option<String>,
}

/// Content type analysis
#[derive(Clone, Debug)]
pub struct ContentInfo {
    /// Content type category
    pub content_category: ContentCategory,
    
    /// Media type details
    pub media_type: Option<MediaType>,
    
    /// File extension
    pub file_extension: Option<String>,
    
    /// Whether this is a streaming request
    pub is_streaming: bool,
    
    /// Whether this is an initialization segment
    pub is_init_segment: bool,
    
    /// Segment/chunk information
    pub segment_info: Option<SegmentInfo>,
    
    /// Quality/resolution info
    pub quality_info: QualityInfo,
}

/// Content categories
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentCategory {
    Video,
    Audio,
    Image,
    Document,
    Stylesheet,
    Script,
    Html,
    Data(DataFormat),
    StreamingManifest,
    MediaSegment,
    Other,
}

/// Data formats
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataFormat {
    Json,
    Xml,
    Text,
    Binary,
}

/// Media type details
#[derive(Clone, Debug)]
pub struct MediaType {
    pub format: String,
    pub codec: Option<String>,
    pub container: Option<String>,
}

/// Segment information for streaming content
#[derive(Clone, Debug)]
pub struct SegmentInfo {
    pub index: Option<u32>,
    pub sequence_number: Option<u32>,
    pub is_chunk: bool,
    pub duration: Option<f32>,
}

/// Quality information
#[derive(Clone, Debug, Default)]
pub struct QualityInfo {
    pub resolution: Option<Resolution>,
    pub bitrate: Option<String>,
    pub quality_label: Option<String>,
}

/// Resolution information
#[derive(Clone, Debug)]
pub struct Resolution {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub label: String,
}

/// Authentication information (hashed for security)
#[derive(Clone, Debug)]
pub struct AuthInfo {
    pub auth_type: String,
    pub auth_hash: String,
    pub requires_auth: bool,
}

/// Network information
#[derive(Clone, Debug)]
pub struct NetworkInfo {
    pub client_ip: String,
    pub port: u16,
    pub is_local: bool,
    pub protocol: Option<String>,
}

impl HttpContext {
    pub fn from_request<B: hyper::body::Body>(req: &Request<B>, client_addr: SocketAddr) -> Self {
        let headers = Self::extract_headers(req.headers());
        let uri = req.uri().clone();
        
        // Parse URI components
        let path = uri.path().to_string();
        let query_params = Self::parse_query_params(uri.query());
        
        // Analyze content
        let content_info = Self::analyze_content(&path, &query_params, &headers);
        
        // Extract authentication info
        let auth_info = Self::extract_auth_info(&headers);
        
        // Network info
        let network_info = Self::extract_network_info(client_addr, &headers);
        
        HttpContext {
            client_addr,
            request_method: req.method().clone(),
            request_uri: uri,
            path,
            query_params,
            headers,
            content_info,
            auth_info,
            network_info,
        }
    }
    
    fn extract_headers(headers_map: &HeaderMap) -> RequestHeaders {
        RequestHeaders {
            content_type: Self::get_header_string(headers_map, &CONTENT_TYPE),
            etag: Self::get_header_string(headers_map, &ETAG),
            last_modified: Self::get_header_string(headers_map, &LAST_MODIFIED),
            byte_range: Self::get_header_string(headers_map, &RANGE),
            accept: Self::get_header_string(headers_map, &ACCEPT),
            accept_language: Self::get_header_string(headers_map, &ACCEPT_LANGUAGE),
            user_agent: Self::get_header_string(headers_map, &USER_AGENT),
            authorization: Self::get_header_string(headers_map, &AUTHORIZATION),
            content_range: Self::get_header_string(headers_map, &CONTENT_RANGE),
            host: Self::get_header_string(headers_map, &HOST),
            referer: Self::get_header_string(headers_map, &HeaderName::from_static("referer")),
            cache_control: Self::get_header_string(headers_map, &HeaderName::from_static("cache-control")),
            if_none_match: Self::get_header_string(headers_map, &HeaderName::from_static("if-none-match")),
            if_modified_since: Self::get_header_string(headers_map, &HeaderName::from_static("if-modified-since")),
        }
    }
    
    fn parse_query_params(query: Option<&str>) -> HashMap<String, String> {
        let mut params = HashMap::new();
        
        if let Some(query_str) = query {
            for pair in query_str.split('&') {
                let mut parts = pair.split('=');
                if let Some(key) = parts.next() {
                    if !key.is_empty() {
                        let value = parts.next().unwrap_or("").to_string();
                        params.insert(key.to_string(), value);
                    }
                }
            }
        }
        
        params
    }
    
    fn analyze_content(path: &str, query_params: &HashMap<String, String>, headers: &RequestHeaders) -> ContentInfo {
        let path_lower = path.to_lowercase();
        
        // Determine file extension
        let file_extension = path.split('.')
            .last()
            .filter(|ext| !ext.is_empty() && !path_lower.ends_with(ext)) // Avoid false positives
            .map(|ext| ext.to_lowercase());
        
        // Analyze based on extension and path patterns
        let (content_category, media_type, is_streaming, is_init_segment) = 
            Self::categorize_content(&path_lower, &file_extension, query_params);
        
        // Extract segment info for streaming content
        let segment_info = if is_streaming {
            Self::extract_segment_info(&path_lower, query_params)
        } else {
            None
        };
        
        // Extract quality info
        let quality_info = Self::extract_quality_info(&path_lower, query_params, headers);
        
        ContentInfo {
            content_category,
            media_type,
            file_extension,
            is_streaming,
            is_init_segment,
            segment_info,
            quality_info,
        }
    }
    
    fn categorize_content(
        path: &str,
        file_extension: &Option<String>,
        query_params: &HashMap<String, String>
    ) -> (ContentCategory, Option<MediaType>, bool, bool) {
        let mut is_streaming = false;
        let mut is_init_segment = false;
        let mut media_type = None;
        
        let category = match file_extension.as_deref() {
            // Video formats
            Some("mp4") | Some("avi") | Some("mov") | Some("mkv") | Some("webm") | Some("flv") => {
                media_type = Some(MediaType {
                    format: "video".to_string(),
                    codec: Self::detect_codec(path, query_params),
                    container: file_extension.clone(),
                });
                ContentCategory::Video
            }
            
            // Audio formats
            Some("mp3") | Some("wav") | Some("ogg") | Some("flac") | Some("aac") | Some("m4a") => {
                media_type = Some(MediaType {
                    format: "audio".to_string(),
                    codec: Self::detect_codec(path, query_params),
                    container: file_extension.clone(),
                });
                ContentCategory::Audio
            }
            
            // Streaming manifests
            Some("m3u8") => {
                is_streaming = true;
                ContentCategory::StreamingManifest
            }
            Some("mpd") => {
                is_streaming = true;
                ContentCategory::StreamingManifest
            }
            
            // Media segments
            Some("ts") | Some("m4s") | Some("chk") => {
                is_streaming = true;
                ContentCategory::MediaSegment
            }
            
            // Images
            Some("jpg") | Some("jpeg") | Some("png") | Some("gif") | Some("webp") | Some("svg") | Some("bmp") => {
                ContentCategory::Image
            }
            
            // Documents
            Some("pdf") | Some("doc") | Some("docx") | Some("xls") | Some("xlsx") | Some("ppt") | Some("pptx") => {
                ContentCategory::Document
            }
            
            // Web assets
            Some("css") => ContentCategory::Stylesheet,
            Some("js") => ContentCategory::Script,
            Some("html") | Some("htm") => ContentCategory::Html,
            
            // Data formats
            Some("json") => ContentCategory::Data(DataFormat::Json),
            Some("xml") => ContentCategory::Data(DataFormat::Xml),
            Some("txt") => ContentCategory::Data(DataFormat::Text),
            
            _ => {
                // Analyze based on path patterns
                if path.contains("/video/") || path.contains("/media/") || path.contains("/movie/") {
                    ContentCategory::Video
                } else if path.contains("/audio/") || path.contains("/music/") {
                    ContentCategory::Audio
                } else if path.contains("/stream/") || path.contains("/hls/") || path.contains("/dash/") {
                    is_streaming = true;
                    ContentCategory::StreamingManifest
                } else if path.contains("/segment") || path.contains("/chunk") || path.contains("/fragment") {
                    is_streaming = true;
                    ContentCategory::MediaSegment
                } else if path.contains("/init") || query_params.get("init").map(|v| v == "1").unwrap_or(false) {
                    is_streaming = true;
                    is_init_segment = true;
                    ContentCategory::MediaSegment
                } else if path.contains("/image/") || path.contains("/img/") {
                    ContentCategory::Image
                } else {
                    ContentCategory::Other
                }
            }
        };
        
        (category, media_type, is_streaming, is_init_segment)
    }
    
    fn detect_codec(path: &str, query_params: &HashMap<String, String>) -> Option<String> {
        // Check query parameters
        if let Some(codec) = query_params.get("codec").or_else(|| query_params.get("c")) {
            return Some(codec.clone());
        }
        
        // Check path patterns
        let path_lower = path.to_lowercase();
        if path_lower.contains("h264") || path_lower.contains("avc") {
            Some("h264".to_string())
        } else if path_lower.contains("h265") || path_lower.contains("hevc") {
            Some("h265".to_string())
        } else if path_lower.contains("vp9") {
            Some("vp9".to_string())
        } else if path_lower.contains("av1") {
            Some("av1".to_string())
        } else if path_lower.contains("aac") {
            Some("aac".to_string())
        } else if path_lower.contains("mp3") {
            Some("mp3".to_string())
        } else {
            None
        }
    }
    
    fn extract_segment_info(path: &str, query_params: &HashMap<String, String>) -> Option<SegmentInfo> {
        let mut segment_info = SegmentInfo {
            index: None,
            sequence_number: None,
            is_chunk: path.contains("chunk"),
            duration: None,
        };
        
        // Try to extract from path first
        segment_info.index = Self::extract_number_from_path(path, &[
            (r"segment[_-]?(\d+)", 1),
            (r"chunk[_-]?(\d+)", 1),
            (r"/(\d+)\.(ts|m4s|chk)", 1),
            (r"seg[_-]?(\d+)", 1),
            (r"(\d+)_\d+\.ts", 1),
            (r"fragment[_-]?(\d+)", 1),
        ]);
        
        // Try sequence number
        segment_info.sequence_number = Self::extract_number_from_path(path, &[
            (r"_(\d+)\.ts$", 1),
            (r"seq[_-]?(\d+)", 1),
            (r"sequence[_-]?(\d+)", 1),
        ]);
        
        // Check query parameters
        if segment_info.index.is_none() {
            segment_info.index = query_params.get("segment")
                .or_else(|| query_params.get("seg"))
                .or_else(|| query_params.get("index"))
                .and_then(|s| s.parse().ok());
        }
        
        // Extract duration
        if let Some(duration_str) = query_params.get("duration") {
            segment_info.duration = duration_str.parse().ok();
        }
        
        Some(segment_info)
    }
    
    fn extract_number_from_path(path: &str, patterns: &[(&str, usize)]) -> Option<u32> {
        for (pattern, group) in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(captures) = re.captures(path) {
                    if let Some(matched) = captures.get(*group) {
                        if let Ok(num) = matched.as_str().parse::<u32>() {
                            return Some(num);
                        }
                    }
                }
            }
        }
        None
    }
    
    fn extract_quality_info(
        path: &str,
        query_params: &HashMap<String, String>,
        headers: &RequestHeaders
    ) -> QualityInfo {
        let mut quality_info = QualityInfo::default();
        
        // Check query parameters first
        if let Some(res_str) = query_params.get("resolution")
            .or_else(|| query_params.get("res"))
            .or_else(|| query_params.get("quality"))
            .or_else(|| query_params.get("q"))
        {
            quality_info.resolution = Self::parse_resolution(res_str);
            quality_info.quality_label = Some(res_str.clone());
        }
        
        // Check bitrate
        if let Some(br_str) = query_params.get("bitrate")
            .or_else(|| query_params.get("br"))
            .or_else(|| query_params.get("rate"))
        {
            quality_info.bitrate = Some(br_str.clone());
        }
        
        // If not in query, check path
        if quality_info.resolution.is_none() {
            quality_info.resolution = Self::extract_resolution_from_path(path);
        }
        
        // Check Accept header for quality preferences
        if let Some(accept) = &headers.accept {
            if accept.contains("q=") {
                // Parse quality factor from Accept header
                for part in accept.split(',') {
                    if part.contains("q=") {
                        if let Some(q_value) = part.split("q=").nth(1) {
                            quality_info.quality_label = Some(format!("q{}", q_value.split(';').next().unwrap_or("")));
                            break;
                        }
                    }
                }
            }
        }
        
        quality_info
    }
    
    fn parse_resolution(res_str: &str) -> Option<Resolution> {
        let res_lower = res_str.to_lowercase();
        
        // Parse WxH format (1920x1080)
        if let Some((w_str, h_str)) = res_lower.split_once('x') {
            if let (Ok(width), Ok(height)) = (w_str.parse::<u32>(), h_str.parse::<u32>()) {
                return Some(Resolution {
                    width: Some(width),
                    height: Some(height),
                    label: res_str.to_string(),
                });
            }
        }
        
        // Standard labels
        let (width, height, label) = match res_lower.as_str() {
            "4k" | "2160p" | "uhd" => (Some(3840), Some(2160), "4K".to_string()),
            "2k" | "1440p" => (Some(2560), Some(1440), "2K".to_string()),
            "1080p" | "fullhd" => (Some(1920), Some(1080), "1080p".to_string()),
            "720p" | "hd" => (Some(1280), Some(720), "720p".to_string()),
            "480p" | "sd" => (Some(854), Some(480), "480p".to_string()),
            "360p" => (Some(640), Some(360), "360p".to_string()),
            "240p" => (Some(426), Some(240), "240p".to_string()),
            "144p" => (Some(256), Some(144), "144p".to_string()),
            _ => (None, None, res_str.to_string()),
        };
        
        Some(Resolution { width, height, label })
    }
    
    fn extract_resolution_from_path(path: &str) -> Option<Resolution> {
        let patterns = [
            (r"(\d{3,4}[xp])", 1), // 1080p, 720p
            (r"(\d{3,4}x\d{3,4})", 1), // 1920x1080
            (r"(hd|sd|fullhd|4k|2k|uhd)", 1), // качественные обозначения
            (r"/(\d+p)/", 1), // /1080p/
        ];
        
        for (pattern, group) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(captures) = re.captures(path) {
                    if let Some(matched) = captures.get(*group) {
                        return Self::parse_resolution(matched.as_str());
                    }
                }
            }
        }
        
        None
    }
    
    fn extract_auth_info(headers: &RequestHeaders) -> Option<AuthInfo> {
        headers.authorization.as_ref().map(|auth| {
            // Simple hash for security
            let auth_hash = Self::simple_hash(auth);
            
            // Detect auth type
            let auth_type = if auth.starts_with("Bearer ") {
                "bearer".to_string()
            } else if auth.starts_with("Basic ") {
                "basic".to_string()
            } else if auth.starts_with("Digest ") {
                "digest".to_string()
            } else {
                "unknown".to_string()
            };
            
            AuthInfo {
                auth_type,
                auth_hash,
                requires_auth: true,
            }
        })
    }
    
    fn extract_network_info(client_addr: SocketAddr, headers: &RequestHeaders) -> NetworkInfo {
        let ip_str = client_addr.ip().to_string();
        let is_local = client_addr.ip().is_loopback();
        
        // Try to detect protocol from headers
        let protocol = headers.host.as_ref().and_then(|host| {
            if host.starts_with("https://") {
                Some("https".to_string())
            } else if host.starts_with("http://") {
                Some("http".to_string())
            } else {
                None
            }
        });
        
        NetworkInfo {
            client_ip: ip_str,
            port: client_addr.port(),
            is_local,
            protocol,
        }
    }
    
    // Helper methods
    fn get_header_string(headers_map: &HeaderMap, header_name: &HeaderName) -> Option<String> {
        headers_map.get(header_name)
            .and_then(|value| value.to_str().ok())
            .map(|s| s.trim().to_string())
    }
    
    fn simple_hash(s: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
    
    // Public methods for accessing request information
    pub fn is_media_request(&self) -> bool {
        matches!(
            self.content_info.content_category,
            ContentCategory::Video | ContentCategory::Audio
        )
    }
    
    pub fn is_streaming_request(&self) -> bool {
        self.content_info.is_streaming
    }
    
    pub fn is_partial_content(&self) -> bool {
        self.headers.byte_range.is_some() || self.headers.content_range.is_some()
    }
    
    pub fn has_authorization(&self) -> bool {
        self.auth_info.is_some()
    }
    
    pub fn get_cache_priority(&self) -> CachePriority {
        if self.is_streaming_request() {
            CachePriority::High
        } else if self.is_media_request() {
            CachePriority::Medium
        } else if self.has_authorization() {
            CachePriority::Low // Private content
        } else {
            CachePriority::Normal
        }
    }
    
    pub fn should_cache(&self) -> bool {
        // Basic caching decision logic
        !self.has_authorization() || self.network_info.is_local
    }
    
    pub fn get_cache_duration_hint(&self) -> Option<u64> {
        match self.content_info.content_category {
            ContentCategory::Image => Some(86400), // 1 day
            ContentCategory::Stylesheet | ContentCategory::Script => Some(604800), // 1 week
            ContentCategory::StreamingManifest => Some(300), // 5 minutes
            ContentCategory::MediaSegment => Some(3600), // 1 hour
            _ => None,
        }
    }
}

/// Cache priority levels
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CachePriority {
    Critical,
    High,
    Medium,
    Normal,
    Low,
}

// Implement Display for easier debugging
impl std::fmt::Display for HttpContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HttpContext {{\n")?;
        write!(f, "  method: {},\n", self.request_method)?;
        write!(f, "  content: {:?},\n", self.content_info.media_type)?;
        write!(f, "  partial content: {},\n", self.is_partial_content())?;
        write!(f, "  path: {},\n", self.path)?;
        write!(f, "  category: {:?},\n", self.content_info.content_category)?;
        write!(f, "  streaming: {},\n", self.content_info.is_streaming)?;
        write!(f, "  authorized: {},\n", self.has_authorization())?;
        write!(f, "  client: {}:{},\n", self.network_info.client_ip, self.network_info.port)?;
        write!(f, "}}")
    }
}