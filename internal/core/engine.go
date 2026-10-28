package core 

type Analyzer interface{

	Analyze(file *FileData) ([]Alert, error)
	GetPaths() []string

}