Design the analyzer architecture.

Create an abstract Analyzer interface.

Methods

supports()

analyze()

Every analyzer returns AnalysisResult.

Implement

Analyzer

PEAnalyzer

ZIPAnalyzer

PNGAnalyzer

PDFAnalyzer

OfficeAnalyzer

Only PEAnalyzer should contain a placeholder implementation.

All others should raise NotImplementedError.

Follow SOLID principles.

Write unit tests.
