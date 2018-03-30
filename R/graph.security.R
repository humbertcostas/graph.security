#' Returns a sample of the data sets based on the percentage provided by `n` parameter.
#' You can also set the random seed for reproducible samples.
#'
#' @param n Percentage of the sample data set. Values from 0 < n < 1. Default set as 0.1
#' @param rnd.seed Random seed for sample selection. Default set at 1714.
#'
#' @return list of data frames (cves, cpes, cwes, capec, sard)
#' @export
#'
#' @examples
GetSampleDataSet <- function(n = 0.1, rnd.seed = 1714) {
  if ((0 >= n) || (n >= 1)) n = 0.1
  set.seed(seed = rnd.seed)
  # system.file("extdata", "netsec-full.rda", package = "graph.security")
  netsec <- list(cves = netsec.data$datasets$cves[sample(x = nrow(netsec.data$datasets$cves), size = round(n*nrow(netsec.data$datasets$cves))), ],
                 cpes = netsec.data$datasets$cpes[sample(x = nrow(netsec.data$datasets$cpes), size = round(n*nrow(netsec.data$datasets$cpes))), ],
                 cwes = netsec.data$datasets$cwes[sample(x = nrow(netsec.data$datasets$cwes), size = round(n*nrow(netsec.data$datasets$cwes))), ],
                 capec = netsec.data$datasets$capec[sample(x = nrow(netsec.data$datasets$capec), size = round(n*nrow(netsec.data$datasets$capec))), ],
                 sard = netsec.data$datasets$sard[sample(x = nrow(netsec.data$datasets$sard), size = round(n*nrow(netsec.data$datasets$sard))), ])
  # TODO: Reducing factors levels to new size should optimize data frame.
  return(netsec)
}

GetNetworkData <- function(scope = c("CVE-2016-8475", "CVE-2014-8613", "CVE-2008-4915")) {
  # scope <- netsec$datasets$cves$cve.id[sample(nrow(netsec$datasets$cves), 200)]

  # CVEs --> CWEs
  c.cwes <- sapply(netsec.data$datasets$cves$problem.type, function(x) length(jsonlite::fromJSON(x)))
  # One edge
  cves2cwes1 <- netsec.data$datasets$cves[c.cwes == 1, c("cve.id", "problem.type")]
  cves2cwes1$problem.type <- sapply(cves2cwes1$problem.type, function(x) jsonlite::fromJSON(x))
  names(cves2cwes1) <- c("src", "target")

  # Multiple edges
  cves2cwesN <- netsec.data$datasets$cves[c.cwes > 1, c("cve.id", "problem.type")]
  cves2cwesN <- apply(cves2cwesN, 1,
                      function(x) {
                        pt <- jsonlite::fromJSON(x[["problem.type"]])
                        cve <- rep(x[["cve.id"]], length(pt))
                        data.frame(src = cve, target = pt, stringsAsFactors = F)
                      })
  cves2cwesN <- data.table::rbindlist(cves2cwesN)
  # Join edges
  cves2cwes <- dplyr::bind_rows(cves2cwes1, cves2cwesN)

  # CWEs --> CAPECs
  netsec.data$datasets$cwes$Related_Attack_Patterns[is.na(netsec.data$datasets$cwes$Related_Attack_Patterns)] <- "{}"
  c.capec <- sapply(netsec.data$datasets$cwes$Related_Attack_Patterns, function(x) length(jsonlite::fromJSON(x)))
  # One edge
  cwes2capec1 <- netsec.data$datasets$cwes[c.capec == 1, c("Code_Standard", "Related_Attack_Patterns")]
  cwes2capec1$Related_Attack_Patterns <- as.character(sapply(cwes2capec1$Related_Attack_Patterns, function(x) jsonlite::fromJSON(x)))
  names(cwes2capec1) <- c("src", "target")

  # Multiple edges
  cwes2capecN <- netsec.data$datasets$cwes[c.capec > 1, c("Code_Standard", "Related_Attack_Patterns")]
  cwes2capecN <- apply(cwes2capecN, 1,
                      function(x) {
                        capec <- as.character(jsonlite::fromJSON(x[["Related_Attack_Patterns"]]))
                        cwe <- rep(x[["Code_Standard"]], length(capec))
                        data.frame(src = cwe, target = capec, stringsAsFactors = F)
                      })
  cwes2capecN <- data.table::rbindlist(cwes2capecN)
  # Join edges
  cwes2capec <- dplyr::bind_rows(cwes2capec1, cwes2capecN)
  cwes2capec$target <- as.character(sapply(cwes2capec$target, function(x) paste("CAPEC", x, sep = "-")))

  # Filter scope
  scope.cve.cwe <- dplyr::filter(cves2cwes, src %in% scope)
  scope.cve <- data.frame(src = scope[which(!(scope %in% cves2cwes$src))],
                    target = "NVD-CWE-noinfo", stringsAsFactors = F)
  cves2cwes <- dplyr::bind_rows(scope.cve.cwe, scope.cve)

  scope <- unique(cwes2capec$target)
  scope.cwe.capec <- dplyr::filter(cwes2capec, src %in% scope)
  scope.cwe <- data.frame(src = scope[which(!(scope %in% cwes2capec$src))],
                          target = "NVD-CWE-noinfo", stringsAsFactors = F)
  cwes2capec <- dplyr::bind_rows(scope.cwe.capec, scope.cwe)


  # Join all graphs
  gsec <- dplyr::bind_rows(cves2cwes, cwes2capec)
  return(cves2cwes)
}

#' References
#' https://christophergandrud.github.io/networkD3/
#' http://kateto.net/networks-r-igraph
#'