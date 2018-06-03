package types

type File struct{
	Id		string `json:"id"`
	Name	string `json:"name"`
	Size	int64  `json:"size"`
	Date	string `json:"date"`
}

type FilesResponse struct {
	Ok    bool   `json:"ok"`
	Files []File `json:"files"`
}

type FileDownloadRequest struct {
	Id    string `json:"id"`
}
